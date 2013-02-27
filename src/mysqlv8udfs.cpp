#include "stdlib.h"
#include "string.h"
#include "stdarg.h"
#include "mysql.h"
#include "plugin.h"
#include "v8.h"

#define TRUE                            1
#define FALSE                           0
#define STR_TRUE                        "true"
#define STR_FALSE                       "false"
#define JS_MAX_RETURN_VALUE_LENGTH      65535L
unsigned long JS_INITIAL_RETURN_VALUE_LENGTH  = 255;

static v8::Persistent<v8::ObjectTemplate> globalTemplate;
static v8::Persistent<v8::String> str_arguments;
static v8::Persistent<v8::String> str_const_item;
static v8::Persistent<v8::String> str_decimals;
static v8::Persistent<v8::String> str_maybe_null;
static v8::Persistent<v8::String> str_max_length;
static v8::Persistent<v8::String> str_name;
static v8::Persistent<v8::String> str_type;
static v8::Persistent<v8::String> str_value;
static v8::Persistent<v8::String> str_STRING_RESULT;
static v8::Persistent<v8::String> str_INT_RESULT;
static v8::Persistent<v8::String> str_DECIMAL_RESULT;
static v8::Persistent<v8::String> str_REAL_RESULT;
static v8::Persistent<v8::String> str_ROW_RESULT;
static v8::Persistent<v8::String> str_NOT_FIXED_DEC;
static v8::Persistent<v8::Context> jsDaemonContext;
static v8::HeapStatistics *js_daemon_heap_statistics;

#define MSG_MISSING_SCRIPT              "Missing script argument."
#define MSG_SCRIPT_MUST_BE_STRING       "Script argument must be a string."
#define MSG_V8_ALLOCATION_FAILED        "Failed to allocate v8 resources."
#define MSG_RESULT_ALLOCATION_FAILED    "Failed to allocate result buffer."
#define MSG_CREATE_CONTEXT_FAILED       "Failed to create context."
#define MSG_SCRIPT_COMPILATION_FAILED   "Error compiling script."
#define MSG_STATIC_SCRIPT_REQUIRED      "Script should be static."
#define MSG_RUNTIME_SCRIPT_ERROR        "Runtime script error."
#define MSG_NO_UDF_DEFINED              "Script does not define a function udf(){}."
#define MSG_NO_AGG_DEFINED              "Script does not define a function agg(){}."
#define MSG_NO_CLEAR_DEFINED            "Script does not define a function clear(){}."
#define MSG_ERR_SETTING_API_CONSTANT    "Operation not supported."
#define MSG_UNSUPPORTED_TYPE            "You cannot set an arugment to this type."
#define MSG_JS_DAEMON_STARTUP           "JS daemon startup."
#define MSG_JS_DAEMON_SHUTDOWN          "JS daemon shutdown."

#define LOG_ERR(a) fprintf(stderr, "\n%s", a);

#define INIT_ERROR                      1
#define INIT_SUCCESS                    0

const char* ToCString(const v8::String::Utf8Value& value) {
  return *value ? *value : "<string conversion failed>";
}

//get the exception string from javascript try/catch block.
const char* getExceptionString(v8::TryCatch* try_catch) {
  v8::String::Utf8Value exception(try_catch->Exception());
  const char* exception_string = ToCString(exception);
  return exception_string;
}

/**
 *
 * Wrappin UDF ARGs
 *
 */
typedef v8::Handle<v8::Value> (*ARG_EXTRACTOR)(UDF_ARGS*, unsigned int);

//extractor to get a STRING udf argument as a javascript string.
v8::Handle<v8::Value> getStringArgValue(UDF_ARGS *args, unsigned int i){
  return v8::String::New(args->args[i], args->lengths[i]);
}

//extractor to get a INT udf argument as a javascript number (or int)
v8::Handle<v8::Value> getIntArgValue(UDF_ARGS *args, unsigned int i){
  long long int_val = *((long long *)args->args[i]);
  if (int_val >> 31) return v8::Number::New((double)int_val);
  else return v8::Integer::New(int_val);
}

//extractor to get a REAL udf argument as a javascript number
v8::Handle<v8::Value> getRealArgValue(UDF_ARGS *args, unsigned int i){
  return v8::Number::New(*((double *)args->args[i]));
}

//struct to keep track any resources we need to execute the udf
//these are mainly v8 handles
typedef struct st_v8_resources {
  v8::Persistent<v8::Context> context;    //the v8 context used to execute the script
  my_bool compiled;                       //1 if script already holds a script compiled in the init function
  v8::Persistent<v8::Script> script;      //handle to user script pre-compiled in the init function
  v8::Persistent<v8::Function> udf;       //
  v8::Persistent<v8::Function> agg;       //
  v8::Persistent<v8::Function> clear;     //
  v8::Persistent<v8::Array> arguments;    //arguments array exposed to the script
  v8::Handle<v8::Value> *arg_values;  //argument values passed to udf functions
  ARG_EXTRACTOR *arg_extractors;        //array of extractor functions to transfer udf arguments to script arguments
  char *result;                          //buffer to hold the string result of executing the script
  unsigned long max_result_length;      //number of bytes allocated for the result buffer.
} V8RES;

//set up arguments.
//Any arguments beyond the initial "script" argument
//are available in a global array called arguments
//this func is called in the init function to create that array.
my_bool setupArguments(V8RES *v8res, UDF_ARGS* args, char *message) {
  //allocate room for extractors
  v8res->arg_extractors = (ARG_EXTRACTOR*)malloc(
    args->arg_count * sizeof(ARG_EXTRACTOR)
  );
  if (v8res->arg_extractors == NULL) {
    strcpy(message, MSG_V8_ALLOCATION_FAILED);
    return INIT_ERROR;
  }
  v8::Handle<v8::Value> arg_value;

  v8::Local<v8::Array> arguments = v8::Array::New(args->arg_count - 1);
  if (arguments.IsEmpty()) {
    strcpy(message, MSG_V8_ALLOCATION_FAILED);
    return INIT_ERROR;
  }
  v8res->context->Global()->Set(str_arguments, arguments);
  v8res->arguments = v8::Persistent<v8::Array>::New(arguments);
  for (unsigned int i = 1; i < args->arg_count; i++) {
    //for each argument, find a suitable extractor.
    //(the extractor translates value from mysql to v8 land)
    ARG_EXTRACTOR arg_extractor;
    my_bool was_decimal = FALSE;
    switch (args->arg_type[i]) {
      case ROW_RESULT:
        args->arg_type[i] = STRING_RESULT;
      case STRING_RESULT:
        arg_extractor = getStringArgValue;
        break;
      case INT_RESULT:
        arg_extractor = getIntArgValue;
        break;
      case DECIMAL_RESULT:
        //explicitly coerce decimals into reals.
        //we don't really like to do this but since MySQL doesn't offer
        //a CAST from decimal to real we do it automatically.
        //users that want to apply true decimal semantics to their decimal
        //values should CAST their decimal values to strings instead and
        //handle the string to decimal conversion inside the script themselves.
        args->arg_type[i] = REAL_RESULT;
        //mark as was decimal in case we need to get the value.
        was_decimal = TRUE;
      case REAL_RESULT:
        arg_extractor = getRealArgValue;
        break;
    }
    if (args->args[i] == NULL) {
      //this is a non-constant argument.
      //store the extractor so we can call it in the row-level function
      v8res->arg_extractors[i] = arg_extractor;
      arg_value = v8::Null();
    }
    else {
      //this is a constant argument.
      //call the extractor only once here to obtain its value
      if (was_decimal) {
        //if it was DECIMAL, we coerce it to REAL.
        //but in this phase, the coercion has not taken place yet,
        //so if we need the value (as is the case now)
        //we need to use the old string extractor
        arg_value = getStringArgValue(args, i)->ToNumber();
      }
      else {
        arg_value = (*arg_extractor)(args, i);
      }
      v8res->arg_extractors[i] = NULL;
    }
    v8res->arguments->Set(i - 1, arg_value);
  }
  return INIT_SUCCESS;
}

v8::Local<v8::Object> createArgumentObject(V8RES *v8res, UDF_ARGS *args, unsigned int i){
  v8::Local<v8::Object> argumentObject = v8::Object::New();
  argumentObject->Set(str_name, v8::String::New(args->attributes[i], args->attribute_lengths[i]));
  argumentObject->Set(str_type, v8::Uint32::New(args->arg_type[i]));
  argumentObject->Set(str_max_length, v8::Number::New((double)args->lengths[i]));
  ARG_EXTRACTOR arg_extractor = v8res->arg_extractors[i];
  v8::Handle<v8::Value> arg_value;
  if (arg_extractor == NULL) {
    //argumentObject->Set(str_value, v8res->arguments->Get(i - 1));
    argumentObject->Set(str_const_item, v8::True());
  }
  else {
    //argumentObject->Set(str_value, v8::Null());
    argumentObject->Set(str_const_item, v8::False());
  }
  argumentObject->Set(str_maybe_null, args->maybe_null[i] == TRUE ? v8::True() : v8::False());
  arg_value = v8res->arguments->Get(i - 1);
  v8res->arg_values[i-1] = arg_value;
  argumentObject->Set(str_value, arg_value);
  return argumentObject;
}

my_bool setupArgumentObjects(V8RES *v8res, UDF_ARGS* args, char *message){
  //allocate room for value array
  v8res->arg_values = (v8::Handle<v8::Value> *)malloc((args->arg_count - 1) * sizeof(v8::Handle<v8::Value>));
  if (v8res->arg_values == NULL) {
    strcpy(message, MSG_V8_ALLOCATION_FAILED);
    return INIT_ERROR;
  }
  for (unsigned int i = 1; i < args->arg_count; i++) {
    v8res->arguments->Set(i - 1, createArgumentObject(v8res, args, i));
  }
  return INIT_SUCCESS;
}

void updateArgumentObjects(V8RES *v8res, UDF_ARGS* args){
  ARG_EXTRACTOR arg_extractor;
  v8::Handle<v8::Value> val;
  for (unsigned int i = 1; i < args->arg_count; i++) {
    arg_extractor = v8res->arg_extractors[i];
    //if this is a constant argument,
    //the value is already set in the init function
    //so we can skip it.
    if (arg_extractor == NULL) continue;
    //extract and store the argument value
    if (args->args[i] == NULL) val = v8::Null();
    else val = (*arg_extractor)(args, i);
    v8res->arg_values[i - 1] = val;
    v8res->arguments->Get(i - 1)->ToObject()->Set(str_value, val);
  }
}

//this is called in the init after running the js init.
//this reads back the type field of the argument objects
my_bool updateArgsFromArgumentObjects(V8RES *v8res, UDF_ARGS *args){
  v8::Local<v8::Value> type;
  v8::Local<v8::Uint32> intType;
  v8::Local<v8::Object> argument;
  Item_result _type;
  for (unsigned int i = 1; i < args->arg_count; i++) {
    argument = v8res->arguments->Get(i - 1)->ToObject();
    _type = (Item_result)argument->Get(str_type)->ToUint32()->Value();
    if (_type == args->arg_type[i]) continue;
    switch (_type) {
      case STRING_RESULT:
        args->arg_type[i] = _type;
        if (args->args[i] != NULL) {
          argument->Set(str_value, argument->Get(str_value)->ToString());
        }
        break;
      case REAL_RESULT:
      case INT_RESULT:
        args->arg_type[i] = _type;
        if (args->args[i] != NULL) {
          argument->Set(str_value, argument->Get(str_value)->ToNumber());
        }
        break;
      case DECIMAL_RESULT:
      case ROW_RESULT:
      default:
        return INIT_ERROR;
        break;
    }
  }
  return INIT_SUCCESS;
}

//assign udf argument values to javascript arguments array.
//this is called in the row-level function
void assignArguments(V8RES *v8res, UDF_ARGS* args) {
  ARG_EXTRACTOR arg_extractor;
  v8::Handle<v8::Value> val;
  for (unsigned int i = 1; i < args->arg_count; i++) {
    arg_extractor = v8res->arg_extractors[i];
    //if this is a constant argument,
    //the value is already set in the init function
    //so we can skip it.
    if (arg_extractor == NULL) continue;
    //extract and store the argument value
    if (args->args[i] == NULL) val = v8::Null();
    else val = (*arg_extractor)(args, i);
    v8res->arguments->Set(i - 1, val);
  }
}

//allocate result buffer.
//this is called in the row-level function
//to expand the buffer to fit the current script result.
my_bool alloc_result(V8RES *v8res, unsigned long *length) {
  if (*length <= v8res->max_result_length) return INIT_SUCCESS;
  if (v8res->result != NULL) {
    free(v8res->result);
  }
  v8res->result = (char *)malloc(*length);
  if (v8res->result == NULL) {
    v8res->max_result_length = 0;
    LOG_ERR(MSG_RESULT_ALLOCATION_FAILED);
    return INIT_ERROR;
  }
  v8res->max_result_length = *length;
  return INIT_SUCCESS;
}


//utility to get a udf arg as a javascript string.
v8::Handle<v8::String> getStringArgString(UDF_ARGS *args, unsigned int i){
  return v8::String::New(args->args[i], args->lengths[i]);
}

//utility to get a udf arg as a script handle.
v8::Handle<v8::Script> getScriptArgValue(UDF_ARGS *args, unsigned int i){
  return v8::Script::Compile(getStringArgString(args, i));
}

char* call_udf_return_func(
  v8::Persistent<v8::Function> func,
  UDF_INIT *initid,
  UDF_ARGS *args,
  char *result,
  unsigned long *length,
  my_bool *is_null,
  my_bool *error
){
  V8RES *v8res = (V8RES *)initid->ptr;
  v8::Locker locker;
  v8res->context->Enter();
  v8::HandleScope handle_scope;
  v8::TryCatch try_catch;

  updateArgumentObjects(v8res, args);

  v8::Local<v8::Value> value = func->Call(
    v8res->context->Global(), args->arg_count - 1, v8res->arg_values
  );
  if (value.IsEmpty()) {
    //error calling function
    LOG_ERR(MSG_RUNTIME_SCRIPT_ERROR);
    LOG_ERR(getExceptionString(&try_catch));
    v8res->context->Exit();
    *error = TRUE;
    return NULL;
  }
  if (value->IsNull()) {
    *is_null = TRUE;
    v8res->context->Exit();
    return NULL;
  }
  //return the value returned by the script
  v8::String::AsciiValue ascii(value);
  *length = (unsigned long)ascii.length();
  if (alloc_result(v8res, length) == INIT_ERROR) {
    LOG_ERR(MSG_RESULT_ALLOCATION_FAILED);
    *error = TRUE;
    return NULL;
  }
  strcpy(v8res->result, *ascii);
  v8res->context->Exit();
  return v8res->result;
}

/**
 *  js daemon plugin
 */
v8::Persistent<v8::ObjectTemplate> createGlobalTemplate(){
  v8::Handle<v8::ObjectTemplate> _template = v8::ObjectTemplate::New();
  _template->SetInternalFieldCount(1);
  return v8::Persistent<v8::ObjectTemplate>::New(_template);
}

//create a global object template used to initialize
//the scripts' global execution environment.
v8::Handle<v8::ObjectTemplate> getGlobalTemplate(){
  //static ensures we will only create the template once.
  //TODO: create a daemon plugin that manages shared global resources
//  static v8::Persistent<v8::ObjectTemplate> globalTemplate = createGlobalTemplate();
  return globalTemplate;
}

/**
 *
 *  Wrapping useful udf constants
 *
 */
void setConstant(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info){
  v8::ThrowException(
    v8::Exception::Error(
      v8::String::New(MSG_ERR_SETTING_API_CONSTANT)
    )
  );
}

v8::Handle<v8::Value> getStringResultConstant(v8::Local<v8::String> property, const v8::AccessorInfo& info){
  return v8::Uint32::New(STRING_RESULT);
}

v8::Handle<v8::Value> getRealResultConstant(v8::Local<v8::String> property, const v8::AccessorInfo& info){
  return v8::Uint32::New(REAL_RESULT);
}

v8::Handle<v8::Value> getIntResultConstant(v8::Local<v8::String> property, const v8::AccessorInfo& info){
  return v8::Uint32::New(INT_RESULT);
}

v8::Handle<v8::Value> getRowResultConstant(v8::Local<v8::String> property, const v8::AccessorInfo& info){
  return v8::Uint32::New(ROW_RESULT);
}

v8::Handle<v8::Value> getDecimalResultConstant(v8::Local<v8::String> property, const v8::AccessorInfo& info){
  return v8::Uint32::New(DECIMAL_RESULT);
}

v8::Handle<v8::Value> getNotFixedDecConstant(v8::Local<v8::String> property, const v8::AccessorInfo& info){
  return v8::Uint32::New(NOT_FIXED_DEC);
}

void add_udf_constants(v8::Local<v8::Object> object){
  object->SetAccessor(str_STRING_RESULT, getStringResultConstant, setConstant);
  object->SetAccessor(str_REAL_RESULT, getRealResultConstant, setConstant);
  object->SetAccessor(str_INT_RESULT, getIntResultConstant, setConstant);
  object->SetAccessor(str_ROW_RESULT, getRowResultConstant, setConstant);
  object->SetAccessor(str_DECIMAL_RESULT, getDecimalResultConstant, setConstant);
  object->SetAccessor(str_NOT_FIXED_DEC, getNotFixedDecConstant, setConstant);
}

/**
 *
 *  Wrapping UDF_INIT
 *
 */
v8::Handle<v8::Value> get_const_item(v8::Local<v8::String> property, const v8::AccessorInfo &info){
  UDF_INIT* initid = (UDF_INIT*)v8::Local<v8::External>::Cast(info.Holder()->GetInternalField(0))->Value();
  return initid->const_item ? v8::True() : v8::False();
}

void set_const_item(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info){
  UDF_INIT* initid = (UDF_INIT*)v8::Local<v8::External>::Cast(info.Holder()->GetInternalField(0))->Value();
  initid->const_item = value->BooleanValue() ? 1 : 0;
}

v8::Handle<v8::Value> get_decimals(v8::Local<v8::String> property, const v8::AccessorInfo &info){
  UDF_INIT* initid = (UDF_INIT*)v8::Local<v8::External>::Cast(info.Holder()->GetInternalField(0))->Value();
  return v8::Uint32::New(initid->decimals);
}

void set_decimals(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info){
  UDF_INIT* initid = (UDF_INIT*)v8::Local<v8::External>::Cast(info.Holder()->GetInternalField(0))->Value();
  initid->decimals = value->Uint32Value();
}

v8::Handle<v8::Value> get_max_length(v8::Local<v8::String> property, const v8::AccessorInfo &info){
  UDF_INIT* initid = (UDF_INIT*)v8::Local<v8::External>::Cast(info.Holder()->GetInternalField(0))->Value();
  return v8::Integer::New(initid->max_length);
}

void set_max_length(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info){
  UDF_INIT* initid = (UDF_INIT*)v8::Local<v8::External>::Cast(info.Holder()->GetInternalField(0))->Value();
  initid->max_length = value->IntegerValue();
}

v8::Handle<v8::Value> get_maybe_null(v8::Local<v8::String> property, const v8::AccessorInfo &info){
  UDF_INIT* initid = (UDF_INIT*)v8::Local<v8::External>::Cast(info.Holder()->GetInternalField(0))->Value();
  return initid->maybe_null ? v8::True() : v8::False();
}

void set_maybe_null(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info){
  UDF_INIT* initid = (UDF_INIT*)v8::Local<v8::External>::Cast(info.Holder()->GetInternalField(0))->Value();
  initid->maybe_null = value->BooleanValue() ? 1 : 0;
}

void add_udf_init_accessors(v8::Local<v8::Object> object, UDF_INIT* initid){
  object->SetInternalField(0, v8::External::New(initid));
  object->SetAccessor(str_const_item, get_const_item, set_const_item);
  object->SetAccessor(str_decimals, get_decimals, set_decimals);
  object->SetAccessor(str_max_length, get_max_length, set_max_length);
  object->SetAccessor(str_maybe_null, get_maybe_null, set_maybe_null);
}

/**
 *  js_daemon plugin
 */
v8::HeapStatistics *createHeapStatistics(){
  v8::HeapStatistics *heapStatistics = new v8::HeapStatistics();
  return heapStatistics;
}

void updateHeapStatistics(){
  v8::Locker locker;
  v8::V8::GetHeapStatistics(js_daemon_heap_statistics);
}

int status_var_v8_heap_size_limit(MYSQL_THD thd, struct st_mysql_show_var *var, char *buff){
  var->type = SHOW_INT;
  updateHeapStatistics();
  *buff = (int)js_daemon_heap_statistics->heap_size_limit();
  var->value = buff;
  return 0;
}

int status_var_v8_heap_size_total(MYSQL_THD thd, struct st_mysql_show_var *var, char *buff){
  var->type = SHOW_INT;
  updateHeapStatistics();
  *buff = (int)js_daemon_heap_statistics->total_heap_size();
  var->value = buff;
  return 0;
}

int status_var_v8_heap_size_total_executable(MYSQL_THD thd, struct st_mysql_show_var *var, char *buff){
  var->type = SHOW_INT;
  updateHeapStatistics();
  *buff = (int)js_daemon_heap_statistics->total_heap_size();
  var->value = buff;
  return 0;
}

int status_var_v8_heap_size_used(MYSQL_THD thd, struct st_mysql_show_var *var, char *buff){
  var->type = SHOW_INT;
  updateHeapStatistics();
  *buff = (int)js_daemon_heap_statistics->used_heap_size();
  var->value = buff;
  return 0;
}

int status_var_v8_is_dead(MYSQL_THD thd, struct st_mysql_show_var *var, char *buff){
  var->type = SHOW_CHAR;
  sprintf(buff, "%s", v8::V8::IsDead() ? STR_TRUE : STR_FALSE);
  var->value = buff;
  return 0;
}

int status_var_v8_is_execution_terminating(MYSQL_THD thd, struct st_mysql_show_var *var, char *buff){
  var->type = SHOW_CHAR;
  sprintf(buff, "%s", v8::V8::IsExecutionTerminating() ? STR_TRUE : STR_FALSE);
  var->value = buff;
  return 0;
}

int status_var_v8_is_profiler_paused(MYSQL_THD thd, struct st_mysql_show_var *var, char *buff){
  var->type = SHOW_CHAR;
  sprintf(buff, "%s", v8::V8::IsProfilerPaused() ? STR_TRUE : STR_FALSE);
  var->value = buff;
  return 0;
}

int status_var_v8_version(MYSQL_THD thd, struct st_mysql_show_var *var, char *buff){
  var->type = SHOW_CHAR;
  var->value = (char *)v8::V8::GetVersion();
  return 0;
}

struct st_mysql_show_var js_daemon_status_vars[] =
{
  {"js_v8_heap_size_limit", (char *)&status_var_v8_heap_size_limit, SHOW_FUNC},
  {"js_v8_heap_size_total", (char *)&status_var_v8_heap_size_total, SHOW_FUNC},
  {"js_v8_heap_size_total_executable", (char *)&status_var_v8_heap_size_total_executable, SHOW_FUNC},
  {"js_v8_heap_size_used", (char *)&status_var_v8_heap_size_used, SHOW_FUNC},
  {"js_v8_is_dead", (char *)&status_var_v8_is_dead, SHOW_FUNC},
  {"js_v8_is_execution_terminating", (char *)&status_var_v8_is_execution_terminating, SHOW_FUNC},
  {"js_v8_is_profiler_paused", (char *)&status_var_v8_is_profiler_paused, SHOW_FUNC},
  {"js_v8_version", (char *)&status_var_v8_version, SHOW_FUNC},
  {0, 0, SHOW_UNDEF}
};

static struct st_mysql_sys_var *js_daemon_system_vars[]= {
  NULL
};

my_bool js_check_arguments(UDF_ARGS *args, char *message){
  //validate arguments
  if (args->arg_count < 1) {
    strcpy(message, MSG_MISSING_SCRIPT);
    return INIT_ERROR;
  }
  if (args->arg_type[0] != STRING_RESULT) {
    strcpy(message, MSG_SCRIPT_MUST_BE_STRING);
    return INIT_ERROR;
  }
  return INIT_SUCCESS;
}

my_bool js_alloc_resources(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  initid->ptr = (char *)malloc(sizeof(V8RES));
  if (initid->ptr == NULL) {
    strcpy(message, MSG_V8_ALLOCATION_FAILED);
    return INIT_ERROR;
  }
  V8RES *v8res = (V8RES *)initid->ptr;
  v8res->arg_values = NULL;
  v8res->arg_extractors = NULL;
  //allocate room for result (return value)
  v8res->result = NULL;
  v8res->max_result_length = 0;
  if (alloc_result(v8res, &JS_INITIAL_RETURN_VALUE_LENGTH) == INIT_ERROR) {
    strcpy(message, MSG_RESULT_ALLOCATION_FAILED);
    return INIT_ERROR;
  }

  return INIT_SUCCESS;
}

void js_set_initid_defaults(UDF_INIT *initid) {
  //set default properties of the return value.
  initid->max_length = JS_MAX_RETURN_VALUE_LENGTH;  //blob. for varchar, use smaller max_length
  initid->maybe_null = TRUE;                        //script author can return what they like, including null
  initid->const_item = FALSE;                       //script author can always write a non-deterministic script
}

my_bool js_pre_compile(UDF_INIT *initid, UDF_ARGS *args, char *message){
  //check if we can pre-compile the script
  V8RES *v8res = (V8RES *)initid->ptr;
  if (args->args[0] == FALSE) {
    //script argument is not a constant.
    v8res->compiled = 0;
    return INIT_SUCCESS;
  }

  v8::TryCatch try_catch;
  //script argument is a constant, compile it.
  v8res->script = v8::Persistent<v8::Script>::New(
    getScriptArgValue(args, 0)
  );
  if (v8res->script.IsEmpty()) {
    const char *exceptionMessage = getExceptionString(&try_catch);
    strcpy(message, MSG_SCRIPT_COMPILATION_FAILED);
    LOG_ERR(MSG_SCRIPT_COMPILATION_FAILED);
    LOG_ERR(exceptionMessage);
    v8res->context->Exit();
    return INIT_ERROR;
  }
  v8res->compiled = 1;
  return INIT_SUCCESS;
}


#ifdef __cplusplus
extern "C" {
#endif

//the UDF init function.
//called once by the mysql server
//before running the udf row level function
my_bool js_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
  if (js_check_arguments(args, message) == INIT_ERROR) return INIT_ERROR;
  if (js_alloc_resources(initid, args, message) == INIT_ERROR) return INIT_ERROR;
  js_set_initid_defaults(initid);

  //v8 introductory voodoo incantations
  v8::Locker locker;
  v8::HandleScope handle_scope;

  //set up a context
  V8RES *v8res = (V8RES *)initid->ptr;
  v8res->context = v8::Context::New(NULL, getGlobalTemplate());
  if (v8res->context.IsEmpty()) {
    strcpy(message, MSG_CREATE_CONTEXT_FAILED);
    return INIT_ERROR;
  }
  v8res->context->Enter();

  //create and initialize arguments array
  if (setupArguments(v8res, args, message) == INIT_ERROR) return INIT_ERROR;

  if (js_pre_compile(initid, args, message) == INIT_ERROR) return INIT_ERROR;

  v8res->context->Exit();

  return INIT_SUCCESS;
}

my_bool jsudf_init(
  UDF_INIT *initid,
  UDF_ARGS *args,
  char *message
){
  if (js_init(initid, args, message) == INIT_ERROR) {
    return INIT_ERROR;
  }
  V8RES *v8res = (V8RES *)initid->ptr;
  if (v8res->compiled != TRUE) {
    strcpy(message, MSG_STATIC_SCRIPT_REQUIRED);
    return INIT_ERROR;
  }
  //v8 introductory voodoo incantations
  v8::Locker locker;
  v8::TryCatch try_catch;

  v8res->context->Enter();
  v8::HandleScope handle_scope;

  v8::Local<v8::Value> value = v8res->script->Run();
  if (value.IsEmpty()) {
    LOG_ERR(getExceptionString(&try_catch));
    strcpy(message, MSG_RUNTIME_SCRIPT_ERROR);
    v8res->context->Exit();
    return INIT_ERROR;
  }

  v8::Local<v8::Object> global = v8res->context->Global();
  v8::Handle<v8::Value> member;
  v8::Handle<v8::Function> func;

  member = global->Get(v8::String::New("udf"));
  if (!member->IsFunction()) {
    strcpy(message, MSG_NO_UDF_DEFINED);
    v8res->context->Exit();
    return INIT_ERROR;
  }
  func = v8::Handle<v8::Function>::Cast(member);
  v8res->udf = v8::Persistent<v8::Function>::New(func);
  v8res->compiled |= 2;

  //set UDF_INIT variables:
  add_udf_init_accessors(global->GetPrototype()->ToObject(), initid);

  add_udf_constants(global);
  //setup argument objects
  if (setupArgumentObjects(v8res, args, message) == INIT_ERROR) {
    v8res->context->Exit();
    return INIT_ERROR;
  }

  //look if there is an init function, and call it.
  member = global->Get(v8::String::New("init"));
  if (member->IsFunction()) {
    func = v8::Handle<v8::Function>::Cast(member);
    value = func->Call(global, args->arg_count - 1, v8res->arg_values);
    if (value.IsEmpty()) {
      //todo: get exception message
      v8res->context->Exit();
      return INIT_ERROR;
    }
    //
  }
  if (updateArgsFromArgumentObjects(v8res, args) == INIT_ERROR) {
    strcpy(message, MSG_UNSUPPORTED_TYPE);
    v8res->context->Exit();
    return INIT_ERROR;
  }
  v8res->context->Exit();
  return INIT_SUCCESS;
}

my_bool jsagg_init(
  UDF_INIT *initid,
  UDF_ARGS *args,
  char *message
){
  if (jsudf_init(initid, args, message) == INIT_ERROR) {
    return INIT_ERROR;
  }
  V8RES *v8res = (V8RES *)initid->ptr;
  v8::Locker locker;
  v8::TryCatch try_catch;

  v8res->context->Enter();
  //v8::Context::Scope context_scope(v8res->context);
  v8::HandleScope handle_scope;

  v8::Local<v8::Object> global = v8res->context->Global();
  v8::Handle<v8::Value> member;
  v8::Handle<v8::Function> func;

  member = global->Get(v8::String::New("clear"));
  if (!member->IsFunction()) {
    strcpy(message, MSG_NO_CLEAR_DEFINED);
    v8res->context->Exit();
    return INIT_ERROR;
  }
  func = v8::Handle<v8::Function>::Cast(member);
  v8res->clear = v8::Persistent<v8::Function>::New(func);
  v8res->compiled |= 4;

  member = global->Get(v8::String::New("agg"));
  if (!member->IsFunction()) {
    strcpy(message, MSG_NO_AGG_DEFINED);
    v8res->context->Exit();
    return INIT_ERROR;
  }
  func = v8::Handle<v8::Function>::Cast(member);
  v8res->agg = v8::Persistent<v8::Function>::New(func);
  v8res->compiled |= 8;

  v8res->context->Exit();
  return INIT_SUCCESS;
}

//the udf deinit function.
//called once by the mysql server after finishing running the row-level function
//for all rows.
void js_deinit(
  UDF_INIT *initid
){
  if (initid->ptr == NULL) return;
  //clean up v8
  V8RES *v8res = (V8RES *)initid->ptr;
  if (v8res->result != NULL) free(v8res->result);
  if (v8res->arg_extractors != NULL) free(v8res->arg_extractors);
  if (v8res->arg_values != NULL) free(v8res->arg_values);
  //v8 introductory voodoo incantations
  v8::Locker locker;
  if (v8res->compiled & 1) {
    v8res->script.Dispose();
  }
  v8res->arguments.Dispose();
  v8res->context.Dispose();
  v8res->context.Clear();
  free(v8res);
}

void jsudf_deinit(
  UDF_INIT *initid
){
  if (initid->ptr == NULL) return;
  //clean up v8
  V8RES *v8res = (V8RES *)initid->ptr;
  if (v8res->compiled & 2) {
    v8res->udf.Dispose();
    v8res->compiled = TRUE;
  }

  v8::Locker locker;
  v8::TryCatch try_catch;
  v8res->context->Enter();
  //v8::Context::Scope context_scope(v8res->context);
  v8::HandleScope handle_scope;

  v8::Local<v8::Object> global = v8res->context->Global();
  v8::Handle<v8::Value> member = global->Get(v8::String::New("deinit"));
  if (member->IsFunction()) {
    v8::Handle<v8::Function> func = v8::Handle<v8::Function>::Cast(member);
    func->Call(global, 0, v8res->arg_values);
  }
  v8res->context->Exit();
  //TODO: check if a udf_deinit exists, and call it.
  js_deinit(initid);
}

void jsagg_deinit(
  UDF_INIT *initid
){
  if (initid->ptr == NULL) return;
  //clean up v8
  V8RES *v8res = (V8RES *)initid->ptr;
  v8::Locker locker;
  v8::TryCatch try_catch;
  if (v8res->compiled & 8) {
    v8res->agg.Dispose();
  }
  if (v8res->compiled & 4) {
    v8res->clear.Dispose();
  }
  jsudf_deinit(initid);
}

//the udf row-level function. called once for each row
//this runs the user script and returns the value
//of the final javascript expression as string
char *js(
  UDF_INIT *initid,
  UDF_ARGS *args,
  char *result,
  unsigned long *length,
  my_bool *is_null,
  my_bool *error
){
  //more sacrifices to the v8 deities.
  V8RES *v8res = (V8RES *)initid->ptr;

  v8::Locker locker;
  v8::TryCatch try_catch;
  v8res->context->Enter();
  v8::Context::Scope context_scope(v8res->context);
  v8::HandleScope handle_scope;

  //assign argument array entries for this row;
  assignArguments(v8res, args);

  //get script to execute
  v8::Handle<v8::Script> script;
  if (v8res->compiled == TRUE){ //already compiled.
    script = v8res->script;
  }
  else {                        //compile on the fly
    script = getScriptArgValue(args, 0);
    if (script.IsEmpty()) {
      LOG_ERR(MSG_SCRIPT_COMPILATION_FAILED);
      *error = TRUE;
      v8res->context->Exit();
      return NULL;
    }
  }

  //execute and get value
  v8::Handle<v8::Value> value = script->Run();
  if (value.IsEmpty()){
    LOG_ERR(MSG_RUNTIME_SCRIPT_ERROR);
    LOG_ERR(getExceptionString(&try_catch));
    *error = TRUE;
    v8res->context->Exit();
    return NULL;
  }

  //return the value returned by the script
  v8::String::AsciiValue ascii(value);
  *length = (unsigned long)ascii.length();
  if (alloc_result(v8res, length) == INIT_ERROR) {
    LOG_ERR(MSG_RESULT_ALLOCATION_FAILED);
    *error = TRUE;
    return NULL;
  }
  strcpy(v8res->result, *ascii);
  v8res->context->Exit();
  return v8res->result;
}

char* jsudf(
  UDF_INIT *initid,
  UDF_ARGS *args,
  char *result,
  unsigned long *length,
  my_bool *is_null,
  my_bool *error
){
  V8RES *v8res = (V8RES *)initid->ptr;
  return call_udf_return_func(
    v8res->udf,
    initid, args,
    result, length,
    is_null, error
  );
}

char* jsagg(
  UDF_INIT *initid,
  UDF_ARGS *args,
  char *result,
  unsigned long *length,
  my_bool *is_null,
  my_bool *error
){
  V8RES *v8res = (V8RES *)initid->ptr;
  return call_udf_return_func(
    v8res->agg,
    initid, args,
    result, length,
    is_null, error
  );
}

void jsagg_clear(
  UDF_INIT *initid,
  my_bool *error
){
  V8RES *v8res = (V8RES *)initid->ptr;
  v8::Locker locker;
  v8::TryCatch try_catch;

  v8res->context->Enter();
  v8::Context::Scope context_scope(v8res->context);
  v8::HandleScope handle_scope;

  v8::Handle<v8::Value> argv[0] = {};
  v8res->clear->Call(v8res->context->Global(), 0, argv);
  v8res->context->Exit();
}

void jsagg_add(
  UDF_INIT *initid,
  UDF_ARGS *args,
  my_bool *is_null,
  my_bool *error
){
  V8RES *v8res = (V8RES *)initid->ptr;
  v8::Locker locker;
  v8::TryCatch try_catch;

  v8res->context->Enter();
  v8::Context::Scope context_scope(v8res->context);
  v8::HandleScope handle_scope;

  updateArgumentObjects(v8res, args);

  v8res->udf->Call(v8res->context->Global(), args->arg_count - 1, v8res->arg_values);
  v8res->context->Exit();
}

struct st_mysql_daemon js_daemon_info = {
  MYSQL_DAEMON_INTERFACE_VERSION
};

static int js_daemon_plugin_init(MYSQL_PLUGIN){
  LOG_ERR(MSG_JS_DAEMON_STARTUP);
  v8::Locker locker;
  v8::HandleScope handle_scope;
  js_daemon_heap_statistics = createHeapStatistics();
  jsDaemonContext = v8::Context::New();
  jsDaemonContext->Enter();
  globalTemplate = createGlobalTemplate();

  str_STRING_RESULT = v8::Persistent<v8::String>::New(v8::String::New("STRING_RESULT"));
  str_INT_RESULT = v8::Persistent<v8::String>::New(v8::String::New("INT_RESULT"));
  str_DECIMAL_RESULT = v8::Persistent<v8::String>::New(v8::String::New("DECIMAL_RESULT"));
  str_REAL_RESULT = v8::Persistent<v8::String>::New(v8::String::New("REAL_RESULT"));
  str_ROW_RESULT = v8::Persistent<v8::String>::New(v8::String::New("ROW_RESULT"));
  str_DECIMAL_RESULT = v8::Persistent<v8::String>::New(v8::String::New("DECIMAL_RESULT"));
  str_NOT_FIXED_DEC = v8::Persistent<v8::String>::New(v8::String::New("NOT_FIXED_DEC"));

  str_arguments = v8::Persistent<v8::String>::New(v8::String::New("arguments"));
  str_const_item = v8::Persistent<v8::String>::New(v8::String::New("const_item"));
  str_decimals = v8::Persistent<v8::String>::New(v8::String::New("decimals"));
  str_maybe_null = v8::Persistent<v8::String>::New(v8::String::New("maybe_null"));
  str_max_length = v8::Persistent<v8::String>::New(v8::String::New("max_length"));
  str_name = v8::Persistent<v8::String>::New(v8::String::New("name"));
  str_type = v8::Persistent<v8::String>::New(v8::String::New("type"));
  str_value = v8::Persistent<v8::String>::New(v8::String::New("value"));

  jsDaemonContext->Exit();
  return 0;
}

static int js_daemon_plugin_deinit(MYSQL_PLUGIN){
  v8::Locker locker;
  v8::HandleScope handle_scope;
  jsDaemonContext->Enter();
  globalTemplate.Dispose();

  str_STRING_RESULT.Dispose();
  str_INT_RESULT.Dispose();
  str_DECIMAL_RESULT.Dispose();
  str_REAL_RESULT.Dispose();
  str_ROW_RESULT.Dispose();
  str_DECIMAL_RESULT.Dispose();
  str_NOT_FIXED_DEC.Dispose();

  str_arguments.Dispose();
  str_const_item.Dispose();
  str_decimals.Dispose();
  str_maybe_null.Dispose();
  str_max_length.Dispose();
  str_name.Dispose();
  str_type.Dispose();
  str_value.Dispose();

  jsDaemonContext->Exit();
  jsDaemonContext.Dispose();
  LOG_ERR(MSG_JS_DAEMON_SHUTDOWN);
  v8::V8::Dispose();
  return 0;
}

mysql_declare_plugin(js_daemon)
{
  MYSQL_DAEMON_PLUGIN,
  &js_daemon_info,
  "js_daemon",
  "Roland Bouman",
  "Javascript Daemon",
  PLUGIN_LICENSE_GPL,
  js_daemon_plugin_init, /* Plugin Init */
  js_daemon_plugin_deinit, /* Plugin Deinit */
  0x0100 /* 1.0 */,
  js_daemon_status_vars,      /* status variables                */
  js_daemon_system_vars,      /* system variables                */
  NULL                        /* config options                  */
}
mysql_declare_plugin_end;

#ifdef __cplusplus
};
#endif
