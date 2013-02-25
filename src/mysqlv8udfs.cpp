#include "stdlib.h"
#include "string.h"
#include "stdarg.h"
#include "mysql.h"
#include "v8.h"

#define TRUE                            1
#define FALSE                           0
#define JS_MAX_RETURN_VALUE_LENGTH      65535L
unsigned long JS_INITIAL_RETURN_VALUE_LENGTH  = 255;

#define MSG_MISSING_SCRIPT              "Missing script argument."
#define MSG_SCRIPT_MUST_BE_STRING       "Script argument must be a string."
#define MSG_RESOURCE_ALLOCATION_FAILED  "Failed to allocate v8 resources."
#define MSG_CREATE_CONTEXT_FAILED       "Failed to create context."
#define MSG_SCRIPT_COMPILATION_FAILED   "Error compiling script."
#define MSG_STATIC_SCRIPT_REQUIRED      "Script should be static."
#define MSG_RUNTIME_SCRIPT_ERROR        "Runtime script error."
#define MSG_NO_UDF_DEFINED              "Script does not define a udf."
#define MSG_ERR_SETTING_API_CONSTANT    "Operation not supported."

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

//this is used to implement the built-in console.log function.
//this allows script authors to write to the mysql error log.
v8::Handle<v8::Value> Log(const v8::Arguments& args) {
  v8::Handle<v8::Value> value = args[0];
  v8::String::AsciiValue ascii(value);
  fprintf(stderr, "\n%s", *ascii);
  return v8::Undefined();
}

//
v8::Handle<v8::ObjectTemplate> getConsoleTemplate(){
  v8::Handle<v8::ObjectTemplate> console = v8::ObjectTemplate::New();
  console->Set(v8::String::New("log"), v8::FunctionTemplate::New(Log));
  return console;
}

//create a console object
v8::Handle<v8::Value> getBuiltinConsole(
  v8::Local<v8::String> property,
  const v8::AccessorInfo& info
) {
  return getConsoleTemplate()->NewInstance();
}

v8::Handle<v8::Value> getStringResultConstant(
  v8::Local<v8::String> property,
  const v8::AccessorInfo& info
){
  return v8::Uint32::New(STRING_RESULT);
}

v8::Handle<v8::Value> getRealResultConstant(
  v8::Local<v8::String> property,
  const v8::AccessorInfo& info
){
  return v8::Uint32::New(REAL_RESULT);
}

v8::Handle<v8::Value> getIntResultConstant(
  v8::Local<v8::String> property,
  const v8::AccessorInfo& info
){
  return v8::Uint32::New(INT_RESULT);
}

v8::Handle<v8::Value> getRowResultConstant(
  v8::Local<v8::String> property,
  const v8::AccessorInfo& info
){
  return v8::Uint32::New(ROW_RESULT);
}

v8::Handle<v8::Value> getDecimalResultConstant(
  v8::Local<v8::String> property,
  const v8::AccessorInfo& info
){
  return v8::Uint32::New(DECIMAL_RESULT);
}

v8::Handle<v8::Value> getNotFixedDecConstant(
  v8::Local<v8::String> property,
  const v8::AccessorInfo& info
){
  return v8::Uint32::New(NOT_FIXED_DEC);
}

void setConstant(
  v8::Local<v8::String> property,
  v8::Local<v8::Value> value,
  const v8::AccessorInfo& info
){
  v8::ThrowException(
    v8::Exception::Error(
      v8::String::New(MSG_ERR_SETTING_API_CONSTANT)
    )
  );
}

//create a global object template used to initialize
//the scripts' global execution environment.
v8::Handle<v8::ObjectTemplate> getGlobalTemplate(){
  v8::Handle<v8::ObjectTemplate> global = v8::ObjectTemplate::New();
  //global->SetAccessor(v8::String::New("console"), getBuiltinConsole);

  //add the result constants (useful if user wants to change the argument types)
  global->SetAccessor(v8::String::New("STRING_RESULT"), getStringResultConstant, setConstant);
  global->SetAccessor(v8::String::New("REAL_RESULT"), getRealResultConstant, setConstant);
  global->SetAccessor(v8::String::New("INT_RESULT"), getIntResultConstant, setConstant);
  global->SetAccessor(v8::String::New("ROW_RESULT"), getRowResultConstant, setConstant);
  global->SetAccessor(v8::String::New("DECIMAL_RESULT"), getDecimalResultConstant, setConstant);

  //
  global->SetAccessor(v8::String::New("NOT_FIXED_DEC"), getNotFixedDecConstant, setConstant);
  return global;
}

//ARG_EXTRACTOR = pointer to an extractor function
typedef v8::Handle<v8::Value> (*ARG_EXTRACTOR)(UDF_ARGS*, unsigned int);

//extractor to get a STRING udf argument as a javascript string.
v8::Handle<v8::Value> getStringArgValue(
  UDF_ARGS *args,
  unsigned int i
){
  return v8::String::New(
    args->args[i],
    args->lengths[i]
  );
}

//extractor to get a INT udf argument as a javascript number (or int)
v8::Handle<v8::Value> getIntArgValue(
  UDF_ARGS *args,
  unsigned int i
){
  long long int_val = *((long long *)args->args[i]);
  if (int_val >> 31) return v8::Number::New((double)int_val);
  else return v8::Integer::New(int_val);
}

//extractor to get a REAL udf argument as a javascript number
v8::Handle<v8::Value> getRealArgValue(
  UDF_ARGS *args,
  unsigned int i
){
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
  ARG_EXTRACTOR *arg_extractors;        //array of extractor functions to transfer udf arguments to script arguments
  char *result;                          //buffer to hold the string result of executing the script
  unsigned long max_result_length;      //number of bytes allocated for the result buffer.
} V8RES;


//set up arguments.
//Any arguments beyond the initial "script" argument
//are available in a global array called arguments
//this func is called in the init function to create that array.
void setupArguments(V8RES *v8res, UDF_ARGS* args) {
  v8::Local<v8::Array> arguments = v8::Array::New(args->arg_count - 1);
  v8res->context->Global()->Set(
    v8::String::New("arguments"),
    arguments
  );
  v8res->arguments = v8::Persistent<v8::Array>::New(arguments);
  for (unsigned int i = 1; i < args->arg_count; i++) {
    //for each argument, find a suitable extractor.
    //(the extractor translates value from mysql to v8 land)
    ARG_EXTRACTOR arg_extractor;
    switch (args->arg_type[i]) {
      case DECIMAL_RESULT:
      case ROW_RESULT:
      case STRING_RESULT:
        arg_extractor = getStringArgValue;
        break;
      case INT_RESULT:
        arg_extractor = getIntArgValue;
        break;
      case REAL_RESULT:
        arg_extractor = getRealArgValue;
        break;
    }
    if (args->args[i] == NULL) {
      //this is a non-constant argument.
      //store the extractor so we can call it in the row-level function
      v8res->arg_extractors[i] = arg_extractor;
    }
    else {
      //this is a constant argument.
      //call the extractor only once here to obtain its value
      v8res->arguments->Set(i - 1, (*arg_extractor)(args, i));
      v8res->arg_extractors[i] = NULL;
    }
  }
}

v8::Local<v8::Object> createArgumentObject(V8RES *v8res, UDF_ARGS *args, unsigned int i){
  v8::Local<v8::Object> argumentObject = v8::Object::New();
  argumentObject->Set(v8::String::New("name"), v8::String::New(args->attributes[i], args->attribute_lengths[i]));
  argumentObject->Set(v8::String::New("max_length"), v8::Number::New((double)args->lengths[i]));
  argumentObject->Set(v8::String::New("maybe_null"), args->maybe_null[i] == TRUE ? v8::True() : v8::True());
  ARG_EXTRACTOR arg_extractor = v8res->arg_extractors[i];
  if (arg_extractor == NULL) {
    argumentObject->Set(v8::String::New("value"), v8res->arguments->Get(i - 1));
  }
  else {
    argumentObject->Set(v8::String::New("value"), v8::Null());
   }
  return argumentObject;
}

void setupArgumentObjects(V8RES *v8res, UDF_ARGS* args){
  for (unsigned int i = 1; i < args->arg_count; i++) {
    v8res->arguments->Set(i - 1, createArgumentObject(v8res, args, i));
  }
}

void updateArgumentObjects(V8RES *v8res, UDF_ARGS* args){
  ARG_EXTRACTOR arg_extractor;
  v8::Handle<v8::Value> val;
  v8::Local<v8::String> valkey = v8::String::New("value");
  for (unsigned int i = 1; i < args->arg_count; i++) {
    arg_extractor = v8res->arg_extractors[i];
    //if this is a constant argument,
    //the value is already set in the init function
    //so we can skip it.
    if (arg_extractor == NULL) continue;
    //extract and store the argument value
    if (args->args[i] == NULL) val = v8::Null();
    else val = (*arg_extractor)(args, i);
    v8res->arguments->Get(i - 1)->ToObject()->Set(valkey, val);
  }
}

//
void updateArgsFromArgumentObjects(V8RES *v8res, UDF_ARGS *args){
  v8::Local<v8::String> typekey = v8::String::New("type");
  v8::Local<v8::Value> type;
  v8::Local<v8::Uint32> intType;
  for (unsigned int i = 1; i < args->arg_count; i++) {
    type = v8res->arguments->Get(i - 1)->ToObject()->Get(typekey);
    if (type->IsUint32()) {
      intType = type->ToUint32();
    }
  }
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
  if (*length <= v8res->max_result_length) return TRUE;
  if (v8res->result != NULL) {
    free(v8res->result);
  }
  v8res->result = (char *)malloc(*length);
  if (v8res->result == NULL) {
    v8res->max_result_length = 0;
    LOG_ERR(MSG_RESOURCE_ALLOCATION_FAILED);
    return FALSE;
  }
  v8res->max_result_length = *length;
  return TRUE;
}


//utility to get a udf arg as a javascript string.
v8::Handle<v8::String> getStringArgString(
  UDF_ARGS *args,
  unsigned int i
){
  return v8::String::New(
    args->args[i],
    args->lengths[i]
  );
}

//utility to get a udf arg as a script handle.
v8::Handle<v8::Script> getScriptArgValue(
  UDF_ARGS *args,
  unsigned int i
){
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
  v8::TryCatch try_catch;

  v8res->context->Enter();
  v8::HandleScope handle_scope;

  updateArgumentObjects(v8res, args);

  v8::Handle<v8::Value> argv[0] = {};
  v8::Local<v8::Value> value = func->Call(
    v8res->context->Global(), 0, argv
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
  if (alloc_result(v8res, length) == FALSE) {
    LOG_ERR(MSG_RESOURCE_ALLOCATION_FAILED);
    *error = TRUE;
    return NULL;
  }
  strcpy(v8res->result, *ascii);
  v8res->context->Exit();
  return v8res->result;
}

#ifdef __cplusplus
extern "C" {
#endif

//the UDF init function.
//called once by the mysql server
//before running the udf row level function
my_bool js_init(
  UDF_INIT *initid,
  UDF_ARGS *args,
  char *message
){
  //validate arguments
  if (args->arg_count < 1) {
    strcpy(message, MSG_MISSING_SCRIPT);
    return INIT_ERROR;
  }
  if (args->arg_type[0] != STRING_RESULT) {
    strcpy(message, MSG_SCRIPT_MUST_BE_STRING);
    return INIT_ERROR;
  }
  //allocate main resource
  initid->ptr = (char *)malloc(sizeof(V8RES));
  if (initid->ptr == NULL) {
    strcpy(message, MSG_RESOURCE_ALLOCATION_FAILED);
    return INIT_ERROR;
  }
  V8RES *v8res = (V8RES *)initid->ptr;
  v8res->result = NULL;
  v8res->max_result_length = 0;
  alloc_result(v8res, &JS_INITIAL_RETURN_VALUE_LENGTH);
  v8res->arg_extractors = (ARG_EXTRACTOR*)malloc(
    args->arg_count * sizeof(ARG_EXTRACTOR)
  );
  if (v8res->arg_extractors == NULL) {
    strcpy(message, MSG_RESOURCE_ALLOCATION_FAILED);
    return INIT_ERROR;
  }
  //v8 introductory voodoo incantations
  v8::Locker locker;
  v8::TryCatch try_catch;
  v8::HandleScope handle_scope;

  //set up a context
  v8res->context = v8::Context::New(NULL, getGlobalTemplate());
  if (v8res->context.IsEmpty()) {
    strcpy(message, MSG_CREATE_CONTEXT_FAILED);
    return INIT_ERROR;
  }
  v8res->context->Enter();

  //create and initialize arguments array
  setupArguments(v8res, args);

  //set some properties of the return value.
  initid->max_length = JS_MAX_RETURN_VALUE_LENGTH;
  //script author can return what they like, including null
  initid->maybe_null = TRUE;
  //script author can always write a non-deterministic script
  initid->const_item = FALSE;

  //check if we can pre-compile the script
  if (args->args[0] == FALSE) { //script argument is not a constant.
    v8res->compiled = 0;
  }
  else {                    //script argument is a constant, compile it.
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
  }

  //
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
  //v8::Context::Scope context_scope(v8res->context);
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
  v8::Local<v8::String> _maybe_null = v8::String::New("maybe_null");
  v8::Local<v8::String> _max_length = v8::String::New("max_length");
  v8::Local<v8::String> _decimals = v8::String::New("decimals");
  v8::Local<v8::String> _const_item = v8::String::New("const_item");

  global->Set(_maybe_null, initid->maybe_null ? v8::True() : v8::False());
  global->Set(_max_length, v8::Number::New((double)initid->max_length));
  global->Set(_decimals, v8::Number::New((double)initid->decimals));
  global->Set(_const_item, initid->const_item ? v8::True() : v8::False());

  //setup argument objects
  setupArgumentObjects(v8res, args);

  //look if there is an init function, and call it.
  member = global->Get(v8::String::New("init"));
  if (member->IsFunction()) {
    func = v8::Handle<v8::Function>::Cast(member);
    v8::Handle<v8::Value> argv[0] = {};
    value = func->Call(global, 0, argv);
    if (value.IsEmpty()) {
      //todo: get exception message
      v8res->context->Exit();
      return INIT_ERROR;
    }
    //write the values back to udf init.
    initid->maybe_null = global->Get(_maybe_null)->IsTrue() ? 1 : 0;
    initid->const_item = global->Get(_const_item)->IsTrue() ? 1 : 0;
    initid->decimals = (unsigned int)global->Get(_decimals)->ToNumber()->Value();
    initid->max_length = (unsigned int)global->Get(_max_length)->ToNumber()->Value();
    //
    updateArgsFromArgumentObjects(v8res, args);
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
    strcpy(message, MSG_NO_UDF_DEFINED);
    v8res->context->Exit();
    return INIT_ERROR;
  }
  func = v8::Handle<v8::Function>::Cast(member);
  v8res->clear = v8::Persistent<v8::Function>::New(func);
  v8res->compiled |= 4;

  member = global->Get(v8::String::New("agg"));
  if (!member->IsFunction()) {
    strcpy(message, MSG_NO_UDF_DEFINED);
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

  //v8 introductory voodoo incantations
  v8::Locker locker;
//  v8::TryCatch try_catch;
  if (v8res->compiled & 1) {
    v8res->script.Dispose();
  }
  v8res->arguments.Dispose();
  v8res->context.Dispose();
  v8res->context.Clear();
  if (v8res->result != NULL) free(v8res->result);
  free(v8res->arg_extractors);
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
    v8::Handle<v8::Value> argv[0] = {};
    func->Call(global, 0, argv);
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
  if (alloc_result(v8res, length) == FALSE) {
    LOG_ERR(MSG_RESOURCE_ALLOCATION_FAILED);
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

  v8::Handle<v8::Value> argv[0] = {};
  v8res->udf->Call(v8res->context->Global(), 0, argv);
  v8res->context->Exit();
}

#ifdef __cplusplus
};
#endif
