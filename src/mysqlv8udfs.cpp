#include "stdlib.h"
#include "string.h"
#include "stdarg.h"
#include "dirent.h"
#include "mysql.h"
#include "plugin.h"
#include "v8.h"

#define TRUE                            1
#define FALSE                           0
#define STR_TRUE                        "true"
#define STR_FALSE                       "false"
#define JS_MAX_RETURN_VALUE_LENGTH      65535L
#define UDF_MAX_ERROR_MSG_LENGTH        255

//values for the v8res->compiled bitfield
#define COMPILED_NO                     0
#define COMPILED_YES                    1
#define COMPILED_UDF                    2
#define COMPILED_CLEAR                  4
#define COMPILED_AGG                    8

unsigned long JS_INITIAL_RETURN_VALUE_LENGTH  = 255;

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
#define MSG_JS_DAEMON_STARTUP           "JS daemon starting..."
#define MSG_JS_DAEMON_STARTED           "JS daemon started."
#define MSG_JS_DAEMON_SHUTTING_DOWN     "JS daemon shutting down."
#define MSG_JS_DAEMON_SHUTDOWN          "JS daemon shutdown."
#define MSG_OK                          "Ok."

#define LOG_ERR(a) fprintf(stderr, "\n%s", a);

#define INIT_ERROR                      1
#define INIT_SUCCESS                    0


static v8::Persistent<v8::ObjectTemplate> globalTemplate;
static v8::Persistent<v8::ObjectTemplate> mysqlTemplate;
static v8::Persistent<v8::ObjectTemplate> mysqlClientTemplate;
static v8::Persistent<v8::ObjectTemplate> mysqlConnectionTemplate;
static v8::Persistent<v8::ObjectTemplate> mysqlQueryTemplate;
static v8::Persistent<v8::ObjectTemplate> mysqlQueryResultTemplate;
static v8::Persistent<v8::ObjectTemplate> mysqlExceptionTemplate;

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

static v8::Persistent<v8::String> str_org_name;
static v8::Persistent<v8::String> str_table;
static v8::Persistent<v8::String> str_org_table;
static v8::Persistent<v8::String> str_length;
static v8::Persistent<v8::String> str_primary_key;
static v8::Persistent<v8::String> str_unique_key;
static v8::Persistent<v8::String> str_multiple_key;
static v8::Persistent<v8::String> str_unsigned;
static v8::Persistent<v8::String> str_zerofill;
static v8::Persistent<v8::String> str_binary;
static v8::Persistent<v8::String> str_auto_increment;
static v8::Persistent<v8::String> str_numeric;

static v8::Persistent<v8::String> str_host;
static v8::Persistent<v8::String> str_user;
static v8::Persistent<v8::String> str_password;
static v8::Persistent<v8::String> str_socket;
static v8::Persistent<v8::String> str_schema;
static v8::Persistent<v8::String> str_port;
static v8::Persistent<v8::String> str_flags;

static v8::Persistent<v8::String> str_code;
static v8::Persistent<v8::String> str_message;
static v8::Persistent<v8::String> str_sqlstate;

static v8::Persistent<v8::String> str_CONNECTION_ALREADY_CLOSED;

static v8::Persistent<v8::Context> jsDaemonContext;
static v8::HeapStatistics *js_daemon_heap_statistics;

const char* ToCString(const v8::String::Utf8Value& value) {
  return *value ? *value : "<string conversion failed>";
}

//this is useful to clean up any disposed handles before automatic GC
//if your objects only use memory, let GC handle it.
//but if you have weak persistent handles that connect to real resources
//like database connections, files, sockets etc.
//then those won't be cleaned up immediately after the handle is disposed.
//generally you want to clean those resources up, so you should call this
//to do that.
void force_v8_cleanup(){
  while(!v8::V8::IdleNotification()) {};
}

void setConstant(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info){
  v8::ThrowException(v8::Exception::Error(v8::String::New(MSG_ERR_SETTING_API_CONSTANT)));
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

//create an argument object. This creates a js object for an entry in args
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

//expose UDF_ARGS as javascript objects. used by jsudf and jsarg
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

//update the value member of the argument objects.
//this is called in each run of add and the row-level function.
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

//calls the passed func, and returns its value to mysql./
//this is used to call the udf function for jsudf and the agg function for jsagg.
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
    LOG_ERR(*v8::String::AsciiValue(try_catch.Exception()));
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
 *
 * MySQL bindings
 *
 */
MYSQL *getMySQLConnectionInternal(v8::Local<v8::Object> holder, my_bool throwIfNull = TRUE) {
  MYSQL *mysql = (MYSQL *)v8::Local<v8::External>::Cast(holder->GetInternalField(0))->Value();
  if (mysql == NULL) v8::ThrowException(v8::Exception::Error(str_CONNECTION_ALREADY_CLOSED));
  return mysql;
}

void weakMysqlConnectionCallback(v8::Persistent<v8::Value> object, void* _mysql) {
  LOG_ERR("Cleaning up weak mysql client...");
  //TODO: clean up the connection.
  MYSQL *mysql = (MYSQL *)_mysql;
  if (mysql != NULL) {
    mysql_close(mysql);
  }
  object.Dispose();
}


/**
 *  MySQL bindings: Exception
 *
 */
v8::Persistent<v8::ObjectTemplate> createMysqlExceptionTemplate(){
  v8::Handle<v8::ObjectTemplate> _mysqlExceptionTemplate = v8::ObjectTemplate::New();
  return v8::Persistent<v8::ObjectTemplate>::New(_mysqlExceptionTemplate);
}

void throwMysqlException(int errno, const char* msg, const char* state){
  v8::Local<v8::Object> exception = mysqlExceptionTemplate->NewInstance();
  exception->Set(str_code, v8::Uint32::New(errno));
  exception->Set(str_message, v8::String::New(msg));
  exception->Set(str_sqlstate, v8::String::New(state));
  v8::ThrowException(exception);
}

void throwMysqlClientException(v8::Local<v8::Object> object){
  MYSQL *mysql = getMySQLConnectionInternal(object);
  throwMysqlException(
    mysql_errno(mysql),
    mysql_error(mysql),
    mysql_sqlstate(mysql)
  );
}

MYSQL_STMT* mysqlQueryInternalMysqlStmtGetter(v8::Handle<v8::Object> mysqlQuery);
void throwMysqlStmtException(v8::Local<v8::Object> mysqlQuery){
  MYSQL_STMT *mysql_stmt = mysqlQueryInternalMysqlStmtGetter(mysqlQuery);
  throwMysqlException(
    mysql_stmt_errno(mysql_stmt),
    mysql_stmt_error(mysql_stmt),
    mysql_stmt_sqlstate(mysql_stmt)
  );
}
/**
 *
 *  MySQL bindings Result
 *
 */
MYSQL_RES* mysqlQueryResultInternalMysqlResGetter(v8::Handle<v8::Object> mysqlQueryResult){
  return (MYSQL_RES *)v8::Local<v8::External>::Cast(mysqlQueryResult->GetInternalField(0))->Value();
}

v8::Handle<v8::Value> msyqlQueryResultInternalDoneGetter(v8::Handle<v8::Object> mysqlQueryResult){
  return mysqlQueryResult->GetInternalField(1);
}

void cleanupMysqlQueryResult(v8::Handle<v8::Object> mysqlQueryResult){
  MYSQL_RES* mysql_res = mysqlQueryResultInternalMysqlResGetter(mysqlQueryResult);
  if (mysql_res == NULL) return;
  //exhaust the result set.
  while (mysql_fetch_row(mysql_res));
  //free the result
  mysql_free_result(mysql_res);
  //null the pointer
  mysqlQueryResult->SetInternalField(0, v8::External::New(NULL));
}

void msyqlQueryResultInternalDoneSetter(v8::Handle<v8::Object> mysqlQueryResult, my_bool value){
  //set the actual field
  mysqlQueryResult->SetInternalField(1, value ? v8::True() : v8::False());
}

void mysqlQueryResultDoneSetter(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info){
  v8::Local<v8::Object> mysqlQueryResult = info.Holder();
  if (value == msyqlQueryResultInternalDoneGetter(mysqlQueryResult)) return;
  if (value->IsFalse()) {
    v8::ThrowException(v8::Exception::Error(v8::String::New("Resultset already exhausted")));
    return;
  }
  cleanupMysqlQueryResult(mysqlQueryResult);
  msyqlQueryResultInternalDoneSetter(mysqlQueryResult, TRUE);
}

v8::Handle<v8::Value> mysqlQueryResultDoneGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  return msyqlQueryResultInternalDoneGetter(info.Holder());
}

v8::Handle<v8::Value> msyqlQueryResultInternalBufferedGetter(v8::Handle<v8::Object> mysqlQueryResult){
  return mysqlQueryResult->GetInternalField(2);
}
void msyqlQueryResultInternalBufferedSetter(v8::Handle<v8::Object> mysqlQueryResult, my_bool value){
  mysqlQueryResult->SetInternalField(2, value ? v8::True() : v8::False());
}

v8::Handle<v8::Value> mysqlQueryResultBufferedGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  return msyqlQueryResultInternalBufferedGetter(info.Holder());
}

MYSQL_ROW mysqlQueryResultInternalMysqlRowGetter(v8::Handle<v8::Object> mysqlQueryResult){
  return (MYSQL_ROW)v8::Local<v8::External>::Cast(mysqlQueryResult->GetInternalField(4))->Value();
}

void mysqlQueryResultInternalMysqlRowSetter(v8::Handle<v8::Object> mysqlQueryResult, MYSQL_ROW mysql_row){
  mysqlQueryResult->SetInternalField(4, v8::External::New(mysql_row));
}

typedef v8::Handle<v8::Value> (*FIELD_EXTRACTOR)(const char *value, unsigned long length);

FIELD_EXTRACTOR *mysqlQueryResultInternalExtractorsGetter(v8::Handle<v8::Object> mysqlQueryResult){
  return (FIELD_EXTRACTOR *)v8::Local<v8::External>::Cast(mysqlQueryResult->GetInternalField(5))->Value();
}

void weakMysqlQueryResultCallback(v8::Persistent<v8::Value> object, void* _mysql_res) {
  LOG_ERR("Cleaning up weak mysql query result...");
  v8::HandleScope handle_scope;
  v8::Handle<v8::Object> mysqlQueryResult = object->ToObject();
  FIELD_EXTRACTOR *field_extractors = mysqlQueryResultInternalExtractorsGetter(mysqlQueryResult);
  if (field_extractors != NULL) {
    free(field_extractors);
    mysqlQueryResult->SetInternalField(5, v8::External::New(NULL));
  }
  if (!msyqlQueryResultInternalDoneGetter(mysqlQueryResult)->IsTrue()) {
    msyqlQueryResultInternalDoneSetter(mysqlQueryResult, TRUE);
  }
  cleanupMysqlQueryResult(mysqlQueryResult);
  object.Dispose();
}

void msyqlQueryInternalDoneSetter(v8::Handle<v8::Object> mysqlQuery, v8::Handle<v8::Value> value);
void mysqlQueryResultFetch(v8::Handle<v8::Object> mysqlQueryResult) {
  MYSQL_RES *mysql_res = mysqlQueryResultInternalMysqlResGetter(mysqlQueryResult);
  LOG_ERR("Getting a row");
  MYSQL_ROW mysql_row = mysql_fetch_row(mysql_res);
  if (mysql_row != NULL) {
    LOG_ERR("There are more rows still...");
    mysqlQueryResultInternalMysqlRowSetter(mysqlQueryResult, mysql_row);
    return;
  }
  msyqlQueryResultInternalDoneSetter(mysqlQueryResult, TRUE);

  v8::Local<v8::Object> mysqlQuery = mysqlQueryResult->GetInternalField(3)->ToObject();
  MYSQL *mysql = getMySQLConnectionInternal(mysqlQuery);
  fprintf(stderr, "MYSQL* = %p", mysql);
  LOG_ERR("Check for more...");
  my_bool hasMore = mysql_more_results(mysql);
  LOG_ERR(hasMore ? "we have more" : "we don't have more");
  LOG_ERR("Get next result");
  int more_results = mysql_next_result(mysql);
  if (more_results > 0) {
  LOG_ERR("oops, error.");
    throwMysqlClientException(mysqlQuery);
    return;
  }
  LOG_ERR(more_results == 0 ? "we have more results" : "we dont have more results");
  msyqlQueryInternalDoneSetter(mysqlQuery, more_results == 0 ? v8::True() : v8::False());
}

v8::Handle<v8::Value> mysqlQueryResultField(const v8::Arguments& args) {
  v8::Local<v8::Object> mysqlQueryResult = args.Holder()->ToObject();
  MYSQL_RES *mysql_res = mysqlQueryResultInternalMysqlResGetter(mysqlQueryResult);
  if (mysql_res == NULL) {
    v8::ThrowException(v8::Exception::Error(v8::String::New("Result already exhausted")));
    return v8::Null();
  }

  MYSQL_FIELD *field = NULL;
  switch (args.Length()) {
    case 0: //no argument passed, get the next field.
      field = mysql_fetch_field(mysql_res);
      break;
    case 1: //argument passed.
      if (args[0]->IsUint32()) {
        v8::Local<v8::Uint32> uint = args[0]->ToUint32();
        unsigned long index = uint->Value();
        unsigned int fieldcount = mysql_num_fields(mysql_res);
        if (index < 0 || index > fieldcount) {
          v8::ThrowException(v8::Exception::Error(v8::String::New("Field index out of range")));
          return v8::Null();
        }
        field = mysql_fetch_field_direct(mysql_res, index);
      }
      else {
        v8::ThrowException(v8::Exception::Error(v8::String::New("Argument should be an unsigned integer")));
        return v8::Null();
      }
      break;
    default:
      v8::ThrowException(v8::Exception::Error(v8::String::New("Expect at most 1 argument")));
      return v8::Null();
  }
  if (field == NULL) return v8::Null();
  v8::Local<v8::Object> mysqlQueryField = v8::Object::New();
  mysqlQueryField->Set(str_name, v8::String::New(field->name));
  mysqlQueryField->Set(str_org_name, v8::String::New(field->org_name));
  mysqlQueryField->Set(str_table, v8::String::New(field->table));
  mysqlQueryField->Set(str_org_table, v8::String::New(field->org_table));
  mysqlQueryField->Set(str_schema, v8::String::New(field->db));
  mysqlQueryField->Set(str_decimals, v8::Uint32::New(field->decimals));
  mysqlQueryField->Set(str_length, v8::Uint32::New(field->length));
  mysqlQueryField->Set(str_max_length, v8::Uint32::New(field->max_length));
  mysqlQueryField->Set(str_maybe_null, field->flags & NOT_NULL_FLAG ? v8::False() : v8::True());
  mysqlQueryField->Set(str_primary_key, field->flags & PRI_KEY_FLAG ? v8::True() : v8::False());
  mysqlQueryField->Set(str_unique_key, field->flags & UNIQUE_KEY_FLAG ? v8::True() : v8::False());
  mysqlQueryField->Set(str_multiple_key, field->flags & MULTIPLE_KEY_FLAG ? v8::True() : v8::False());
  mysqlQueryField->Set(str_unsigned, field->flags & UNSIGNED_FLAG ? v8::True() : v8::False());
  mysqlQueryField->Set(str_zerofill, field->flags & ZEROFILL_FLAG ? v8::True() : v8::False());
  mysqlQueryField->Set(str_binary, field->flags & BINARY_FLAG ? v8::True() : v8::False());
  mysqlQueryField->Set(str_auto_increment, field->flags & AUTO_INCREMENT_FLAG ? v8::True() : v8::False());
  mysqlQueryField->Set(str_numeric, field->flags & NUM_FLAG ? v8::True() : v8::False());
  return mysqlQueryField;
}

v8::Handle<v8::Value> mysqlQueryResultRow(const v8::Arguments& args) {
  LOG_ERR("Fetch");
  v8::Local<v8::Object> mysqlQueryResult = args.Holder()->ToObject();
  //get the "done" field
  if (msyqlQueryResultInternalDoneGetter(mysqlQueryResult)->ToBoolean()->Value()) {
    //v8::ThrowException(v8::Exception::Error(v8::String::New("Result already exhausted")));
    return v8::Null();
  }
  v8::Local<v8::Object> row;
  switch (args.Length()) {
    case 0: //no argument passed, create a new one.
      row = v8::Array::New();
      break;
    case 1: //argument passed.
      if (args[0]->IsArray()) row = v8::Local<v8::Array>::Cast(args[0]);
      else
      if (args[0]->IsObject()) row = v8::Local<v8::Object>::Cast(args[0]);
      else {
        v8::ThrowException(v8::Exception::Error(v8::String::New("Argument should be either an array or an object")));
        return v8::Null();
      }
      break;
    default:
      v8::ThrowException(v8::Exception::Error(v8::String::New("Expect at most 1 argument")));
      return v8::Null();
  }

  //get the row. this should have been pre-fetched.
  MYSQL_ROW mysql_row = mysqlQueryResultInternalMysqlRowGetter(mysqlQueryResult);

  //fill the array with values.
  MYSQL_RES *mysql_res = mysqlQueryResultInternalMysqlResGetter(mysqlQueryResult);
  unsigned int i, fieldcount = mysql_num_fields(mysql_res);
  unsigned long *lengths = mysql_fetch_lengths(mysql_res);
  FIELD_EXTRACTOR *field_extractors = mysqlQueryResultInternalExtractorsGetter(mysqlQueryResult);
  if (row->IsArray()) {
    for (i = 0; i < fieldcount; i++) {
      row->Set(i, field_extractors[i](mysql_row[i], lengths[i]));
    }
  }
  else {
    MYSQL_FIELD* fields = mysql_fetch_fields(mysql_res);
    for (i = 0; i < fieldcount; i++) {
      row->Set(v8::String::New(fields[i].name), field_extractors[i](mysql_row[i], lengths[i]));
    }
  }
  //fetch the next row. This automatically sets the done flag.
  mysqlQueryResultFetch(mysqlQueryResult);
  LOG_ERR("Fetch ready.");
  return row;
}

v8::Persistent<v8::ObjectTemplate> createMysqlQueryResultTemplate(){
  v8::Handle<v8::ObjectTemplate> _mysqlQueryResultTemplate = v8::ObjectTemplate::New();
  //0 is the result, 1 is done flag, 2 is buffered flag, 3 is query, 4 is the current row,
  //5 is the extractor array
  _mysqlQueryResultTemplate->SetInternalFieldCount(6);
  _mysqlQueryResultTemplate->SetAccessor(v8::String::New("done"), mysqlQueryResultDoneGetter, mysqlQueryResultDoneSetter);
  _mysqlQueryResultTemplate->SetAccessor(v8::String::New("buffered"), mysqlQueryResultBufferedGetter, setConstant);
  _mysqlQueryResultTemplate->Set(v8::String::New("field"), v8::FunctionTemplate::New(mysqlQueryResultField));
  _mysqlQueryResultTemplate->Set(v8::String::New("row"), v8::FunctionTemplate::New(mysqlQueryResultRow));
  return v8::Persistent<v8::ObjectTemplate>::New(_mysqlQueryResultTemplate);
}

/**
 *  MySQL bindings: Query
 *
 */
v8::Handle<v8::Boolean> msyqlQueryInternalDoneGetter(v8::Handle<v8::Object> mysqlQuery){
  return mysqlQuery->GetInternalField(1)->ToBoolean();
}
void msyqlQueryInternalDoneSetter(v8::Handle<v8::Object> mysqlQuery, v8::Handle<v8::Value> value){
  mysqlQuery->SetInternalField(1, value);
}

v8::Handle<v8::Value> mysqlQueryDoneGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  return msyqlQueryInternalDoneGetter(info.Holder());
}

MYSQL_STMT* mysqlQueryInternalMysqlStmtGetter(v8::Handle<v8::Object> mysqlQuery){
  MYSQL_STMT *mysql_stmt = (MYSQL_STMT *)v8::Local<v8::External>::Cast(mysqlQuery->GetInternalField(4))->Value();
  return mysql_stmt;
}

my_bool mysqlQueryCheckPrepared(v8::Handle<v8::Object> mysqlQuery) {
  return mysqlQuery->GetInternalField(3)->IsTrue() ? TRUE : FALSE;
}

v8::Handle<v8::Value> mysqlQueryPreparedGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  return info.Holder()->GetInternalField(3);
}

v8::Handle<v8::Value> mysqlQueryParamCountGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  v8::Local<v8::Object> holder = info.Holder();
  if (mysqlQueryCheckPrepared(holder) == TRUE) {
    MYSQL_STMT* mysql_stmt = mysqlQueryInternalMysqlStmtGetter(holder);
    unsigned long count = mysql_stmt_param_count(mysql_stmt);
    return v8::Number::New((double)count);
  }
  else {
    return v8::Null();
  }
}

my_bool checkDone(v8::Handle<v8::Object> mysqlQuery){
  if (msyqlQueryInternalDoneGetter(mysqlQuery)->IsTrue()) return TRUE;
  v8::ThrowException(v8::Exception::Error(v8::String::New("Not all results were consumed")));
  return FALSE;
}

void weakMysqlQueryCallback(v8::Persistent<v8::Value> object, void* _mysql) {
  LOG_ERR("Cleaning up weak mysql query...");
  v8::HandleScope handle_scope;
  v8::Local<v8::Object> mysqlQuery = object->ToObject();
  if (mysqlQueryCheckPrepared(mysqlQuery)) {
    MYSQL_STMT *mysql_stmt = mysqlQueryInternalMysqlStmtGetter(mysqlQuery);
    mysql_stmt_close(mysql_stmt);
  }
  object.Dispose();
}

//String field to javascript
v8::Handle<v8::Value> stringFieldExtractor(const char *value, unsigned long length){
  return v8::String::New(value, length);
}

v8::Handle<v8::Value> stringFieldExtractorNullable(const char *value, unsigned long length){
  if (value == NULL) return v8::Null();
  else return stringFieldExtractor(value, length);
}

//int field to javascript
v8::Handle<v8::Value> int16FieldExtractor(const char *value, unsigned long length){
  //not 100% but I think the docs imply that in case of a non-binary value it is safe to assume value is null-terminated
  return v8::Int32::New(atoi(value));
}

v8::Handle<v8::Value> int16FieldExtractorNullable(const char *value, unsigned long length){
  if (value == NULL) return v8::Null();
  else return int16FieldExtractor(value, length);
}

v8::Handle<v8::Value> int32FieldExtractor(const char *value, unsigned long length){
  return v8::Int32::New(atol(value));
}

v8::Handle<v8::Value> int32FieldExtractorNullable(const char *value, unsigned long length){
  if (value == NULL) return v8::Null();
  else return int32FieldExtractor(value, length);
}

v8::Handle<v8::Value> uint32FieldExtractor(const char *value, unsigned long length){
  return v8::Uint32::New(atoll(value));
}

v8::Handle<v8::Value> uint32FieldExtractorNullable(const char *value, unsigned long length){
  if (value == NULL) return v8::Null();
  else return uint32FieldExtractor(value, length);
}

v8::Handle<v8::Value> longFieldExtractor(const char *value, unsigned long length){
  return v8::Number::New(atoll(value));
}

v8::Handle<v8::Value> longFieldExtractorNullable(const char *value, unsigned long length){
  if (value == NULL) return v8::Null();
  else return longFieldExtractor(value, length);
}

v8::Handle<v8::Value> numFieldExtractor(const char *value, unsigned long length){
  return v8::Number::New(atof(value));
}

v8::Handle<v8::Value> numFieldExtractorNullable(const char *value, unsigned long length){
  if (value == NULL) return v8::Null();
  else return numFieldExtractor(value, length);
}

FIELD_EXTRACTOR getFieldExtractor(MYSQL_FIELD* field){
  unsigned int field_flags;
  my_bool is_not_nullable, is_unsigned;
  field_flags = field->flags;
  is_not_nullable = (field_flags & NOT_NULL_FLAG);
  is_unsigned = (field_flags & UNSIGNED_FLAG);
  FIELD_EXTRACTOR field_extractor;
  switch (field->type) {
    case MYSQL_TYPE_TINY:
    case MYSQL_TYPE_YEAR:
      field_extractor = is_not_nullable ? int16FieldExtractor : int16FieldExtractorNullable;
      break;
    case MYSQL_TYPE_SHORT:
      if (is_unsigned) {
        field_extractor = is_not_nullable ? int32FieldExtractor : int32FieldExtractorNullable;
      }
      else {
        field_extractor = is_not_nullable ? int16FieldExtractor : int16FieldExtractorNullable;
      }
      break;
    case MYSQL_TYPE_INT24:
    case MYSQL_TYPE_LONG:
      if (is_unsigned) {
        field_extractor = is_not_nullable ? uint32FieldExtractor : uint32FieldExtractorNullable;
      }
      else {
        field_extractor = is_not_nullable ? int32FieldExtractor : int32FieldExtractorNullable;
      }
      break;
    case MYSQL_TYPE_LONGLONG:
    case MYSQL_TYPE_FLOAT:
    case MYSQL_TYPE_DOUBLE:
      if (is_unsigned) {
        field_extractor = is_not_nullable ? longFieldExtractor : longFieldExtractorNullable;
      }
      else {
        field_extractor = is_not_nullable ? numFieldExtractor : numFieldExtractorNullable;
      }
      break;
    case MYSQL_TYPE_BIT:
      //break;
    case MYSQL_TYPE_TIMESTAMP:
      //break;
    case MYSQL_TYPE_DATE:
      //break;
    case MYSQL_TYPE_TIME:
      //break;
    case MYSQL_TYPE_DATETIME:
      //break;
    case MYSQL_TYPE_NULL:
    case MYSQL_TYPE_STRING:
    case MYSQL_TYPE_VAR_STRING:
    case MYSQL_TYPE_BLOB:
    case MYSQL_TYPE_SET:
    case MYSQL_TYPE_ENUM:
    case MYSQL_TYPE_DECIMAL:
    case MYSQL_TYPE_NEWDECIMAL:
    case MYSQL_TYPE_GEOMETRY:
    default:
      field_extractor = is_not_nullable ? stringFieldExtractor : stringFieldExtractorNullable;
  }
  return field_extractor;
}

void createImmediateQueryResultExtractors(v8::Local<v8::Object> mysqlQueryResult) {
  MYSQL_RES* mysql_res = mysqlQueryResultInternalMysqlResGetter(mysqlQueryResult);
  unsigned int num_fields = mysql_num_fields(mysql_res);
  FIELD_EXTRACTOR *field_extractors = (FIELD_EXTRACTOR *)malloc(sizeof(FIELD_EXTRACTOR) * num_fields);
  mysqlQueryResult->SetInternalField(5, v8::External::New(field_extractors));
  if (field_extractors == NULL) {
    v8::ThrowException(v8::Exception::Error(v8::String::New("Allocation of field extractors array failed")));
    return;
  }
  MYSQL_FIELD *field;
  for (unsigned int i = 0; i < num_fields; i++) {
    field = mysql_fetch_field_direct(mysql_res, i);
    field_extractors[i] = getFieldExtractor(field);
  }
}

v8::Persistent<v8::Object> mysqlImmediateQueryResult(v8::Local<v8::Object> mysqlQuery, my_bool useOrStore) {
  LOG_ERR("Getting a result. Use or store: ");
  LOG_ERR(useOrStore ? "store" : "use");
  v8::Persistent<v8::Object> persistentMysqlQueryResult;
  //get the actual result.
  LOG_ERR("Get connection");
  MYSQL *mysql = getMySQLConnectionInternal(mysqlQuery);
  LOG_ERR("Get result");
  MYSQL_RES *mysql_res = useOrStore ? mysql_store_result(mysql) : mysql_use_result(mysql);

  if (mysql_res == NULL) {
  LOG_ERR("result is null");
    if (mysql_errno(mysql) != 0) {
      throwMysqlClientException(mysqlQuery);
      return persistentMysqlQueryResult;
    }
    //not the kind of query that has a result.
    //TODO: return a special result object with the number of affected rows.
    return persistentMysqlQueryResult;
  }

  v8::Local<v8::Object> mysqlQueryResult = mysqlQueryResultTemplate->NewInstance();
  mysqlQueryResult->SetInternalField(0, v8::External::New(mysql_res));

  //mark this result dependent upon the holder.
  //This prevents the holder from being cleaned up before the result.
  mysqlQueryResult->SetInternalField(3, mysqlQuery);

  //set the result's done flag
  msyqlQueryResultInternalDoneSetter(mysqlQueryResult, mysql_res == NULL);
  if (mysql_res != NULL) {
    mysqlQueryResultFetch(mysqlQueryResult);
  }

  //set the result's buffered flag.
  msyqlQueryResultInternalBufferedSetter(mysqlQueryResult, useOrStore);

  createImmediateQueryResultExtractors(mysqlQueryResult);

  //make the result persistent and set weak hooks.
  persistentMysqlQueryResult = v8::Persistent<v8::Object>::New(mysqlQueryResult);
  persistentMysqlQueryResult.MakeWeak(mysql_res, weakMysqlQueryResultCallback);

  LOG_ERR("Done getting a result");
  return persistentMysqlQueryResult;
}

//TODO: lots of stuff, currently we don't have prepared statement interface covered.
v8::Persistent<v8::Object> mysqlPreparedQueryResult(v8::Local<v8::Object> mysqlQuery, my_bool useOrStore) {
  v8::Persistent<v8::Object> persistentMysqlQueryResult;
  MYSQL_STMT *mysql_stmt = mysqlQueryInternalMysqlStmtGetter(mysqlQuery);
  if (useOrStore == TRUE) {
    int result = mysql_stmt_store_result(mysql_stmt);
    if (result != 0) {
      throwMysqlStmtException(mysqlQuery);
    }
  }
  return persistentMysqlQueryResult;
}

v8::Handle<v8::Value> mysqlQueryResult(const v8::Arguments& args) {
  //holder is the query object on which the result method was called.
  v8::Local<v8::Object> mysqlQuery = args.Holder()->ToObject();
  //if the query's done flag is true, we bail out.
  v8::Handle<v8::Boolean> queryDone = msyqlQueryInternalDoneGetter(mysqlQuery);
  if (queryDone->IsTrue()) {
    v8::ThrowException(v8::Exception::Error(v8::String::New("Results already consumed")));
    return v8::Null();
  }

  my_bool _useOrStore;
  v8::Local<v8::Value> arg;
  switch (args.Length()) {
    case 0:
      _useOrStore = TRUE;
      break;
    case 1: {
      arg = args[0];
      if (!arg->IsBoolean()) {
        v8::ThrowException(v8::Exception::Error(v8::String::New("Argument must be a boolean")));
        return v8::Null();
      }
      _useOrStore = arg->ToBoolean()->Value() ? TRUE : FALSE;
      break;
    }
    default: {
      v8::ThrowException(v8::Exception::Error(v8::String::New("Expect at most 1 argument")));
      return v8::Null();
    }
  }

  v8::Persistent<v8::Object> persistentMysqlQueryResult;
  //TODO: properly handle diff. cases prepared / immediate
  if (mysqlQueryCheckPrepared(mysqlQuery) == TRUE) {
    persistentMysqlQueryResult = mysqlPreparedQueryResult(mysqlQuery, _useOrStore);
  }
  else {
    persistentMysqlQueryResult = mysqlImmediateQueryResult(mysqlQuery, _useOrStore);
  }
  return persistentMysqlQueryResult;
}

v8::Handle<v8::Value> mysqlQueryExecute(const v8::Arguments& args) {
  LOG_ERR("Executing query");
  v8::Local<v8::Object> mysqlQuery = args.Holder()->ToObject();
  //check the done field. if it's not true we can't execute.
  //beware: done maybe True, False, or Null
  if (!checkDone(mysqlQuery)) {
    v8::ThrowException(v8::Exception::Error(v8::String::New("Query not yet done.")));
    return v8::Null();
  }
  //process the arguments (= parameters, relevant for prepared statements)
  switch (args.Length()) {
    case 0:
      break;
    case 1: {
      //TODO: if not prepared, bail out.
      v8::Local<v8::Value> arg = args[0];
      if (!arg->IsArray()) {
        v8::ThrowException(v8::Exception::Error(v8::String::New("Argument must be an Array.")));
        return v8::Null();
      }
      //for now we simply exit. If prepared we should execute with these parameters.
      v8::ThrowException(v8::Exception::Error(v8::String::New("Parameter passing not (yet) supported.")));
      return v8::Null();
    }
    default: {
      v8::ThrowException(v8::Exception::Error(v8::String::New("Expect at most 1 argument")));
      return v8::Null();
    }
  }

  my_ulonglong affected_rows = 0;
  if (mysqlQueryCheckPrepared(mysqlQuery) == TRUE) {
    MYSQL_STMT *mysql_stmt = mysqlQueryInternalMysqlStmtGetter(mysqlQuery);
    if (mysql_stmt_execute(mysql_stmt) != 0) goto execute_error;
    affected_rows = mysql_stmt_affected_rows(mysql_stmt);
  }
  else {
    //get the statement string
    v8::Local<v8::Value> _sql = mysqlQuery->Get(v8::String::New("sql"));
    if (!_sql->IsString()) {
      v8::ThrowException(v8::Exception::Error(v8::String::New("Member sql must be string")));
      return v8::Null();
    }
    v8::Local<v8::String> sql = _sql->ToString();
    v8::String::AsciiValue ascii(sql);

    //execute the statement
    MYSQL *mysql = getMySQLConnectionInternal(mysqlQuery);
    if (mysql_real_query(mysql, *ascii, ascii.length())) goto execute_error;
    affected_rows = mysql_affected_rows(mysql);
  }

  //mark as ready to fetch first result
  msyqlQueryInternalDoneSetter(mysqlQuery, v8::False());
  LOG_ERR("Done executing query");
  return v8::Number::New((double)affected_rows);
execute_error:
  LOG_ERR("Execute error!");
  msyqlQueryInternalDoneSetter(mysqlQuery, v8::True());
  throwMysqlClientException(mysqlQuery);
  return v8::Null();
}

v8::Handle<v8::Value> mysqlQueryPrepare(const v8::Arguments& args) {
  v8::Local<v8::Object> mysqlQuery = args.Holder();
  if (!checkDone(mysqlQuery)) return v8::False();

  if (mysqlQueryCheckPrepared(mysqlQuery)) {
    v8::ThrowException(v8::Exception::Error(v8::String::New("Query already prepared.")));
    return v8::False();
  }
  MYSQL *mysql = getMySQLConnectionInternal(mysqlQuery);
  MYSQL_STMT *mysql_stmt = mysql_stmt_init(mysql);
  if (mysql_stmt == NULL) {
    v8::ThrowException(v8::Exception::Error(v8::String::New("Failed to allocate prepared statement handle.")));
    return v8::False();
  }
  v8::String::AsciiValue ascii(mysqlQuery->Get(v8::String::New("sql"))->ToString());

  int prepare = mysql_stmt_prepare(mysql_stmt, *ascii, ascii.length());
  if (prepare) {
    throwMysqlStmtException(mysqlQuery);
    return v8::False();
  }
  //mark the query as prepared.
  mysqlQuery->SetInternalField(3, v8::True());
  //TODO: BIND PARAMETES
  //int num_params = mysql_stmt_param_count(mysql_stmt);
  //TODO: BIND RESULTS
  //int num_fields = mysql_stmt_field_count(mysql_stmt);

  return v8::True();
}

v8::Persistent<v8::ObjectTemplate> createMysqlQueryTemplate(){
  v8::Handle<v8::ObjectTemplate> _mysqlQueryTemplate = v8::ObjectTemplate::New();
  //0 is the connection pointer, 1 is done flag, 2 is client object,
  //3 is the prepared flag
  //In case of prepared statement:
  //4 is the statement handle,
  _mysqlQueryTemplate->SetInternalFieldCount(5);
  _mysqlQueryTemplate->SetAccessor(v8::String::New("done"), mysqlQueryDoneGetter, setConstant);
  _mysqlQueryTemplate->SetAccessor(v8::String::New("prepared"), mysqlQueryPreparedGetter, setConstant);
  _mysqlQueryTemplate->SetAccessor(v8::String::New("paramCount"), mysqlQueryParamCountGetter, setConstant);
  _mysqlQueryTemplate->Set(v8::String::New("execute"), v8::FunctionTemplate::New(mysqlQueryExecute));
  _mysqlQueryTemplate->Set(v8::String::New("result"), v8::FunctionTemplate::New(mysqlQueryResult));
  _mysqlQueryTemplate->Set(v8::String::New("prepare"), v8::FunctionTemplate::New(mysqlQueryPrepare));
  return v8::Persistent<v8::ObjectTemplate>::New(_mysqlQueryTemplate);
}

v8::Handle<v8::Value> createMysqlQuery(const v8::Arguments& args) {
  if (args.Length() != 1) {
    v8::ThrowException(v8::Exception::Error(v8::String::New("Expect exactly 1 argument")));
    return v8::Null();
  }
  v8::Local<v8::Value> arg = args[0];
  if (!arg->IsString()) {
    v8::ThrowException(v8::Exception::Error(v8::String::New("Argument must be string")));
    return v8::Null();
  }
  //holder is the mysql client object.
  v8::Local<v8::Object> holder = args.Holder()->ToObject();
  MYSQL *mysql = getMySQLConnectionInternal(holder);

  //make a new query object
  v8::Local<v8::Object> mysqlQuery = mysqlQueryTemplate->NewInstance();
  mysqlQuery->SetInternalField(0, v8::External::New(mysql));
  fprintf(stderr, "\nCreated connection, MYSQL* = %p", mysql);
  //False = More results. Null = ready to get first result. True = done.
  msyqlQueryInternalDoneSetter(mysqlQuery, v8::True());
  //mark the query dependent upon the client object.
  mysqlQuery->SetInternalField(2, holder);
  //mark the query as not prepared
  mysqlQuery->SetInternalField(3, v8::False());
  //set the stmt field to null
  mysqlQuery->SetInternalField(4, v8::Null());
  mysqlQuery->Set(v8::String::New("sql"), arg->ToString());
  //deliver the query object.
  v8::Persistent<v8::Object> persistentMysqlQuery = v8::Persistent<v8::Object>::New(mysqlQuery);
  persistentMysqlQuery.MakeWeak(mysql, weakMysqlQueryCallback);
  return persistentMysqlQuery;
}

/**
 *  MySQL bindings: Connection
 *
 */
v8::Handle<v8::Value> mysqlConnectionClose(const v8::Arguments& args) {
  v8::Local<v8::Object> holder = args.Holder();
  MYSQL *mysql = getMySQLConnectionInternal(holder, FALSE);
  if (mysql == NULL) return v8::False();
  mysql_close(mysql);
  holder->SetInternalField(0, v8::External::New(NULL));
  return v8::True();
}

v8::Handle<v8::Value> mysqlConnectionConnectedGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  MYSQL *mysql = getMySQLConnectionInternal(info.Holder(), FALSE);
  return (mysql == NULL) ? v8::False() : v8::True();
}

v8::Handle<v8::Value> mysqlConnectionCommit(const v8::Arguments& args) {
  MYSQL *mysql = getMySQLConnectionInternal(args.Holder());
  if (mysql_commit(mysql)) {
    throwMysqlClientException(args.Holder());
    return v8::Null();
  }
  return v8::True();
}

v8::Handle<v8::Value> mysqlConnectionRollback(const v8::Arguments& args) {
  MYSQL *mysql = getMySQLConnectionInternal(args.Holder());
  if (mysql_rollback(mysql)) {
    throwMysqlClientException(args.Holder());
    return v8::Null();
  }
  return v8::True();
}

v8::Handle<v8::Value> mysqlConnectionHostInfoGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  MYSQL *mysql = getMySQLConnectionInternal(info.Holder());
  return v8::String::New(mysql_get_host_info(mysql));
}

v8::Handle<v8::Value> mysqlConnectionProtocolInfoGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  MYSQL *mysql = getMySQLConnectionInternal(info.Holder());
  return v8::Integer::New(mysql_get_proto_info(mysql));
}

v8::Handle<v8::Value> mysqlConnectionServerInfoGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  MYSQL *mysql = getMySQLConnectionInternal(info.Holder());
  return v8::String::New(mysql_get_server_info(mysql));
}

v8::Handle<v8::Value> mysqlConnectionAffectedRowsGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  MYSQL *mysql = getMySQLConnectionInternal(info.Holder());
  my_ulonglong result = mysql_affected_rows(mysql);
  if (result == (my_ulonglong)~0) {
    throwMysqlClientException(info.Holder());
    return v8::Null();
  }
  return v8::Number::New((double)result);
}

v8::Handle<v8::Value> mysqlConnectionWarningsGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  MYSQL *mysql = getMySQLConnectionInternal(info.Holder());
  return v8::Integer::New(mysql_warning_count(mysql));
}

v8::Handle<v8::Value> mysqlConnectionInsertIdGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  MYSQL *mysql = getMySQLConnectionInternal(info.Holder());
  return v8::Number::New((double)mysql_insert_id(mysql));
}

v8::Handle<v8::Value> mysqlConnectionStatGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  MYSQL *mysql = getMySQLConnectionInternal(info.Holder());
  const char *stat = mysql_stat(mysql);
  if (stat == NULL) {
    throwMysqlClientException(info.Holder());
    return v8::Null();
  }
  return v8::String::New(stat);
}

v8::Handle<v8::Value> mysqlConnectionCharsetGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  MYSQL *mysql = getMySQLConnectionInternal(info.Holder());
  return v8::String::New(mysql_character_set_name(mysql));
}

void mysqlConnectionCharsetSetter(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info) {
  MYSQL *mysql = getMySQLConnectionInternal(info.Holder());
  v8::String::AsciiValue ascii(value);
  if (mysql_set_character_set(mysql, *ascii)) {
    throwMysqlClientException(info.Holder());
  }
}

v8::Persistent<v8::ObjectTemplate> createMysqlConnectionTemplate(){
  v8::Handle<v8::ObjectTemplate> _mysqlConnectionTemplate = v8::ObjectTemplate::New();
  _mysqlConnectionTemplate->SetInternalFieldCount(1);
  _mysqlConnectionTemplate->Set(v8::String::New("close"), v8::FunctionTemplate::New(mysqlConnectionClose));
  _mysqlConnectionTemplate->Set(v8::String::New("commit"), v8::FunctionTemplate::New(mysqlConnectionCommit));
  _mysqlConnectionTemplate->Set(v8::String::New("rollback"), v8::FunctionTemplate::New(mysqlConnectionRollback));
  _mysqlConnectionTemplate->Set(v8::String::New("query"), v8::FunctionTemplate::New(createMysqlQuery));

  //TODO: probably should call affectedRows automatically inside the query object so each query object maintains their own info.
  _mysqlConnectionTemplate->SetAccessor(v8::String::New("affectedRows"), mysqlConnectionAffectedRowsGetter, setConstant);

  _mysqlConnectionTemplate->SetAccessor(v8::String::New("charset"), mysqlConnectionCharsetGetter, mysqlConnectionCharsetSetter);
  _mysqlConnectionTemplate->SetAccessor(v8::String::New("connected"), mysqlConnectionConnectedGetter, setConstant);
  _mysqlConnectionTemplate->SetAccessor(v8::String::New("hostInfo"), mysqlConnectionHostInfoGetter, setConstant);
  _mysqlConnectionTemplate->SetAccessor(v8::String::New("insertId"), mysqlConnectionInsertIdGetter, setConstant);
  _mysqlConnectionTemplate->SetAccessor(v8::String::New("protocolVersion"),  mysqlConnectionProtocolInfoGetter, setConstant);
  _mysqlConnectionTemplate->SetAccessor(v8::String::New("serverVersion"), mysqlConnectionServerInfoGetter, setConstant);
  _mysqlConnectionTemplate->SetAccessor(v8::String::New("stat"), mysqlConnectionStatGetter, setConstant);
  _mysqlConnectionTemplate->SetAccessor(v8::String::New("warnings"), mysqlConnectionWarningsGetter, setConstant);
  return v8::Persistent<v8::ObjectTemplate>::New(_mysqlConnectionTemplate);
}

/**
 *  MySQL bindings: Client
 *
 */
my_bool getStringFromObject(v8::Local<v8::Object> argObject, v8::Persistent<v8::String> key, char *buffer, const char *error) {
  v8::Local<v8::Value> value;
  if (argObject->Has(key)) {
    value = argObject->Get(key);
    if (value->IsString()) {
      v8::String::AsciiValue ascii(value->ToString());
      strcpy(buffer, *ascii);
    }
    else {
      v8::ThrowException(v8::Exception::Error(v8::String::New(error)));
      return FALSE;
    }
  }
  return TRUE;
}

my_bool getUint32FromObject(v8::Local<v8::Object> argObject, v8::Persistent<v8::String> key, unsigned short *buffer, const char *error){
  v8::Local<v8::Value> value;
  if (argObject->Has(key)) {
    value = argObject->Get(key);
    if (value->IsUint32()) {
      *buffer = value->ToUint32()->Value();
    }
    else {
      v8::ThrowException(v8::Exception::Error(v8::String::New(error)));
      return FALSE;
    }
  }
  return TRUE;
}

my_bool getUint64FromObject(v8::Local<v8::Object> argObject, v8::Persistent<v8::String> key, unsigned long *buffer, const char *error){
  v8::Local<v8::Value> value;
  if (argObject->Has(key)) {
    value = argObject->Get(key);
    if (value->IsNumber()) {
      *buffer = value->ToInteger()->Value();
    }
    else {
      v8::ThrowException(v8::Exception::Error(v8::String::New(error)));
      return FALSE;
    }
  }
  return TRUE;
}

v8::Handle<v8::Value> mysqlClientConnect(const v8::Arguments& args) {
  //TODO: create a real mysql connection
  MYSQL *mysql = mysql_init(NULL);
  if (mysql == NULL) {
    LOG_ERR("Error allocating MySQL resource");
    v8::ThrowException(v8::Exception::Error(v8::String::New("Couldn't allocate mysql resource.")));
    return v8::Null();
  }

  v8::HandleScope handle_scope;
  char host[64]; strcpy(host, "localhost");
  char user[16]; strcpy(user, "");
  char password[16]; strcpy(password, "");
  char schema[64]; strcpy(schema, "");
  unsigned short port = 3306;
  char socket[128]; strcpy(socket, "");
  unsigned long flags = CLIENT_IGNORE_SPACE | CLIENT_MULTI_STATEMENTS | CLIENT_MULTI_RESULTS;

  if (args.Length()) {
    v8::Local<v8::Value> arg = args[0];
    if (!arg->IsObject()) {
      v8::ThrowException(v8::Exception::Error(v8::String::New("Argument must be an object.")));
      return v8::Null();
    }
    v8::Local<v8::Object> argObject = arg->ToObject();
    v8::Local<v8::String> key;

    if (getStringFromObject(argObject, str_host, host, "host must be a string.") == FALSE) return v8::Null();
    if (getStringFromObject(argObject, str_user, user, "user must be a string.") == FALSE) return v8::Null();
    if (getStringFromObject(argObject, str_password, password, "password must be a string.") == FALSE) return v8::Null();
    if (getStringFromObject(argObject, str_schema, schema, "schema must be a string.") == FALSE) return v8::Null();
    if (getStringFromObject(argObject, str_socket, socket, "socket must be a string.") == FALSE) return v8::Null();
    if (getUint32FromObject(argObject, str_port, &port, "port must be an integer.") == FALSE) return v8::Null();
    //if (getUint64FromObject(argObject, str_flags, &flags, "flags must be an integer.") == FALSE) return v8::Null();

  }

  if (mysql_real_connect(
    mysql, host, user, password,
    strlen(schema) ? schema : NULL, port,
    strlen(socket) ? socket : NULL, flags
  ) == NULL) {
    LOG_ERR("Error connecting to MySQL");
    LOG_ERR(mysql_error(mysql));
    mysql_close(mysql);
    v8::ThrowException(v8::Exception::Error(v8::String::New("Can't connect to MySQL.")));
    return v8::Null();
  }

  v8::Local<v8::Object> mysqlConnection = mysqlConnectionTemplate->NewInstance();
  mysqlConnection->SetInternalField(0, v8::External::New(mysql));

  v8::Persistent<v8::Object> persistentMysqlConnection = v8::Persistent<v8::Object>::New(mysqlConnection);
  persistentMysqlConnection.MakeWeak(mysql, weakMysqlConnectionCallback);
  return persistentMysqlConnection;
}

v8::Handle<v8::Value> getMySQlClientVersion(v8::Local<v8::String> property, const v8::AccessorInfo &info) {
  return v8::String::New(mysql_get_client_info());
}

v8::Persistent<v8::ObjectTemplate> createMysqlClientTemplate(){
  v8::Handle<v8::ObjectTemplate> _mysqlClientTemplate = v8::ObjectTemplate::New();
  _mysqlClientTemplate->Set(v8::String::New("connect"), v8::FunctionTemplate::New(mysqlClientConnect));
  _mysqlClientTemplate->SetAccessor(v8::String::New("version"), getMySQlClientVersion, setConstant);
  return v8::Persistent<v8::ObjectTemplate>::New(_mysqlClientTemplate);
}

/**
 *  MySQL bindings: "namespace"
 *
 */
v8::Persistent<v8::ObjectTemplate> createMysqlTemplate(){
  v8::Handle<v8::ObjectTemplate> _mysqlTemplate = v8::ObjectTemplate::New();
  _mysqlTemplate->Set(v8::String::New("client"), mysqlClientTemplate->NewInstance());
  return v8::Persistent<v8::ObjectTemplate>::New(_mysqlTemplate);
}

/**
 *  Global Object
 */
v8::Persistent<v8::ObjectTemplate> createGlobalTemplate(){
  v8::Handle<v8::ObjectTemplate> _template = v8::ObjectTemplate::New();
  //internal field is used to bind UDF_INIT pointer.
  _template->SetInternalFieldCount(1);
  _template->Set(v8::String::New("mysql"), mysqlTemplate->NewInstance());
  return v8::Persistent<v8::ObjectTemplate>::New(_template);
}

/**
 *
 *  Wrapping useful udf constants
 *
 */
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
 *
 *  js_daemon plugin
 *
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

/**
 *
 *  UDF utility methods
 *
 */

//check for initial script argument
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

//allocate memory to hold the result.
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

//set some sensible defaults for the UDF's return value
void js_set_initid_defaults(UDF_INIT *initid) {
  //set default properties of the return value.
  initid->max_length = JS_MAX_RETURN_VALUE_LENGTH;  //blob. for varchar, use smaller max_length
  initid->maybe_null = TRUE;                        //script author can return what they like, including null
  initid->const_item = FALSE;                       //script author can always write a non-deterministic script
}

//compile script argument
my_bool js_pre_compile(UDF_INIT *initid, UDF_ARGS *args, char *message){
  //check if we can pre-compile the script
  V8RES *v8res = (V8RES *)initid->ptr;
  if (args->args[0] == FALSE) {
    //script argument is not a constant.
    v8res->compiled = COMPILED_NO;
    return INIT_SUCCESS;
  }

  v8::TryCatch try_catch;
  //script argument is a constant, compile it.
  v8res->script = v8::Persistent<v8::Script>::New(
    getScriptArgValue(args, 0)
  );
  if (v8res->script.IsEmpty()) {
    strcpy(message, MSG_SCRIPT_COMPILATION_FAILED);
    LOG_ERR(MSG_SCRIPT_COMPILATION_FAILED);
    LOG_ERR(*v8::String::AsciiValue(try_catch.Exception()));
    v8res->context->Exit();
    return INIT_ERROR;
  }
  v8res->compiled = COMPILED_YES;
  return INIT_SUCCESS;
}


#ifdef __cplusplus
extern "C" {
#endif

//the js UDF init function.
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
  v8res->context = v8::Context::New(NULL, globalTemplate);
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

my_bool jserr_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  if (js_init(initid, args, message) == INIT_ERROR) {
    if (strcmp(message, MSG_SCRIPT_COMPILATION_FAILED)) return INIT_ERROR;
  }
  return INIT_SUCCESS;
}

//The jsudf init function
my_bool jsudf_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
  if (js_init(initid, args, message) == INIT_ERROR) {
    return INIT_ERROR;
  }
  V8RES *v8res = (V8RES *)initid->ptr;
  if (v8res->compiled != COMPILED_YES) {
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
    LOG_ERR(*v8::String::AsciiValue(try_catch.Exception()));
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
  v8res->compiled |= COMPILED_UDF;

  //set UDF_INIT variables.
  //in this particular case, we need the prototype, since that is
  //the object that was created from our template, and that is the object
  //that has the internal field that we need to interface with initid.
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
      v8::Local<v8::String> exception = try_catch.Exception()->ToString();
      exception->WriteAscii(message, 0, exception->Length() > UDF_MAX_ERROR_MSG_LENGTH ? UDF_MAX_ERROR_MSG_LENGTH : exception->Length());
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

//The jsagg init function
my_bool jsagg_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
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
  v8res->compiled |= COMPILED_CLEAR;

  member = global->Get(v8::String::New("agg"));
  if (!member->IsFunction()) {
    strcpy(message, MSG_NO_AGG_DEFINED);
    v8res->context->Exit();
    return INIT_ERROR;
  }
  func = v8::Handle<v8::Function>::Cast(member);
  v8res->agg = v8::Persistent<v8::Function>::New(func);
  v8res->compiled |= COMPILED_AGG;

  v8res->context->Exit();
  return INIT_SUCCESS;
}

//the udf deinit function.
//called once by the mysql server after finishing running the row-level function
//for all rows.
void js_deinit(UDF_INIT *initid){
  if (initid->ptr == NULL) return;
  //clean up v8
  V8RES *v8res = (V8RES *)initid->ptr;
  if (v8res->result != NULL) free(v8res->result);
  if (v8res->arg_extractors != NULL) free(v8res->arg_extractors);
  if (v8res->arg_values != NULL) free(v8res->arg_values);
  //v8 introductory voodoo incantations
  v8::Locker locker;
  if (v8res->compiled & COMPILED_YES) {
    v8res->script.Dispose();
  }
  v8res->arguments.Dispose();
  v8res->context.Dispose();
  v8res->context.Clear();
  free(v8res);

  //TODO: mark somewhere if we need to force cleanup, and only do the
  //clean up if the mark is set.
  force_v8_cleanup();
}

void jserr_deinit(UDF_INIT *initid) {
  if (initid->ptr == NULL) return;
  js_deinit(initid);
}

//The jsudf deinit function
void jsudf_deinit(UDF_INIT *initid){
  if (initid->ptr == NULL) return;
  //clean up v8
  V8RES *v8res = (V8RES *)initid->ptr;
  if (v8res->compiled & COMPILED_UDF) {
    v8res->udf.Dispose();
    v8res->compiled = TRUE;
  }

  v8::Locker locker;
  v8::TryCatch try_catch;
  v8res->context->Enter();
  //v8::Context::Scope context_scope(v8res->context);
  v8::HandleScope handle_scope;

  //check if a udf_deinit exists; if so, call it.
  v8::Local<v8::Object> global = v8res->context->Global();
  v8::Handle<v8::Value> member = global->Get(v8::String::New("deinit"));
  if (member->IsFunction()) {
    v8::Handle<v8::Function> func = v8::Handle<v8::Function>::Cast(member);
    func->Call(global, 0, v8res->arg_values);
  }

  v8res->context->Exit();
  js_deinit(initid);
}

//The jsagg deinit function
void jsagg_deinit(UDF_INIT *initid){
  if (initid->ptr == NULL) return;
  //clean up v8
  V8RES *v8res = (V8RES *)initid->ptr;
  v8::Locker locker;
  v8::TryCatch try_catch;
  if (v8res->compiled & COMPILED_AGG) {
    v8res->agg.Dispose();
  }
  if (v8res->compiled & COMPILED_CLEAR) {
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
  if (v8res->compiled == COMPILED_YES){ //already compiled.
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
    LOG_ERR(*v8::String::AsciiValue(try_catch.Exception()));
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

char *jserr(
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

  try_catch.SetVerbose(true);
  try_catch.SetCaptureMessage(true);

  //assign argument array entries for this row;
  assignArguments(v8res, args);

  int lineno = 0;
  int startColumn = 0;
  int endColumn = 0;

  //get script to execute
  v8::Handle<v8::Script> script = getScriptArgValue(args, 0);
  if (script.IsEmpty()) {
    LOG_ERR(MSG_SCRIPT_COMPILATION_FAILED);
    v8::String::AsciiValue ascii1(try_catch.Exception());
    v8::Local<v8::Message> message = try_catch.Message();
    lineno = message->GetLineNumber();
    startColumn = message->GetStartColumn();
    endColumn = message->GetEndColumn();

    *length = 60 + (endColumn - startColumn) + (unsigned long)ascii1.length();
    if (alloc_result(v8res, length) == INIT_ERROR) {
      LOG_ERR(MSG_RESULT_ALLOCATION_FAILED);
      *error = TRUE;
      return NULL;
    }
    sprintf(v8res->result, "Line %u, columns %u - %u: %s", lineno, startColumn, endColumn, *ascii1);
    *length = strlen(v8res->result);
    v8res->context->Exit();
    return v8res->result;
  }

  //execute and get value
  v8::Handle<v8::Value> value = script->Run();
  if (value.IsEmpty()){
    LOG_ERR(MSG_RUNTIME_SCRIPT_ERROR);
    v8::String::AsciiValue ascii(try_catch.Exception());
    v8::Local<v8::Message> message = try_catch.Message();
    startColumn = message->GetStartColumn();
    endColumn = message->GetEndColumn();

    *length = 60 + (unsigned long)ascii.length();
    if (alloc_result(v8res, length) == INIT_ERROR) {
      LOG_ERR(MSG_RESULT_ALLOCATION_FAILED);
      *error = TRUE;
      return NULL;
    }
    sprintf(v8res->result, "Line %u, columns %u - %u: %s", lineno, startColumn, endColumn, *ascii);
    *length = strlen(v8res->result);
    v8res->context->Exit();
    return v8res->result;
  }
  v8res->context->Exit();

  //return the value returned by the script
  *length = strlen(MSG_OK);
  return (char *)MSG_OK;
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

  mysqlExceptionTemplate = createMysqlExceptionTemplate();
  mysqlQueryResultTemplate = createMysqlQueryResultTemplate();
  mysqlQueryTemplate = createMysqlQueryTemplate();
  mysqlConnectionTemplate = createMysqlConnectionTemplate();
  mysqlClientTemplate = createMysqlClientTemplate();
  mysqlTemplate = createMysqlTemplate();

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

  str_org_name = v8::Persistent<v8::String>::New(v8::String::New("originalName"));
  str_table = v8::Persistent<v8::String>::New(v8::String::New("table"));
  str_org_table = v8::Persistent<v8::String>::New(v8::String::New("originalTable"));
  str_length = v8::Persistent<v8::String>::New(v8::String::New("displayLength"));
  str_primary_key = v8::Persistent<v8::String>::New(v8::String::New("primaryKey"));
  str_unique_key = v8::Persistent<v8::String>::New(v8::String::New("uniqueKey"));
  str_multiple_key = v8::Persistent<v8::String>::New(v8::String::New("multipleKey"));
  str_unsigned = v8::Persistent<v8::String>::New(v8::String::New("unsigned"));
  str_zerofill = v8::Persistent<v8::String>::New(v8::String::New("zerofill"));
  str_binary = v8::Persistent<v8::String>::New(v8::String::New("binary"));
  str_auto_increment = v8::Persistent<v8::String>::New(v8::String::New("autoIncrement"));
  str_numeric = v8::Persistent<v8::String>::New(v8::String::New("numeric"));

  str_host = v8::Persistent<v8::String>::New(v8::String::New("host"));
  str_user = v8::Persistent<v8::String>::New(v8::String::New("user"));
  str_password = v8::Persistent<v8::String>::New(v8::String::New("password"));
  str_socket = v8::Persistent<v8::String>::New(v8::String::New("socket"));
  str_schema = v8::Persistent<v8::String>::New(v8::String::New("schema"));
  str_port = v8::Persistent<v8::String>::New(v8::String::New("port"));
  str_flags = v8::Persistent<v8::String>::New(v8::String::New("flags"));

  str_code = v8::Persistent<v8::String>::New(v8::String::New("code"));
  str_message = v8::Persistent<v8::String>::New(v8::String::New("message"));
  str_sqlstate = v8::Persistent<v8::String>::New(v8::String::New("sqlstate"));

  str_CONNECTION_ALREADY_CLOSED = v8::Persistent<v8::String>::New(v8::String::New("Connection already closed."));

  jsDaemonContext->Exit();

  LOG_ERR(MSG_JS_DAEMON_STARTED);
  return 0;
}

static int js_daemon_plugin_deinit(MYSQL_PLUGIN){
  LOG_ERR(MSG_JS_DAEMON_SHUTTING_DOWN);
  v8::Locker locker;
  v8::HandleScope handle_scope;
  jsDaemonContext->Enter();

  globalTemplate.Dispose();

  mysqlTemplate.Dispose();
  mysqlClientTemplate.Dispose();
  mysqlConnectionTemplate.Dispose();
  mysqlQueryTemplate.Dispose();
  mysqlQueryResultTemplate.Dispose();
  mysqlExceptionTemplate.Dispose();

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

  str_org_name.Dispose();
  str_table.Dispose();
  str_org_table.Dispose();
  str_length.Dispose();
  str_primary_key.Dispose();
  str_unique_key.Dispose();
  str_multiple_key.Dispose();
  str_unsigned.Dispose();
  str_zerofill.Dispose();
  str_binary.Dispose();
  str_auto_increment.Dispose();
  str_numeric.Dispose();

  str_host.Dispose();
  str_schema.Dispose();
  str_user.Dispose();
  str_password.Dispose();
  str_socket.Dispose();
  str_port.Dispose();
  str_flags.Dispose();

  str_code.Dispose();
  str_message.Dispose();
  str_sqlstate.Dispose();

  str_CONNECTION_ALREADY_CLOSED.Dispose();

  jsDaemonContext->Exit();
  jsDaemonContext.Dispose();
  v8::V8::Dispose();

  LOG_ERR(MSG_JS_DAEMON_SHUTDOWN);
  return 0;
}

mysql_declare_plugin(js_daemon)
{
  MYSQL_DAEMON_PLUGIN,
  &js_daemon_info,
  "js_daemon",
  "Roland Bouman",
  "Javascript Daemon - Manages resources for the js* UDFs.",
  PLUGIN_LICENSE_GPL,
  js_daemon_plugin_init,      /* Plugin Init */
  js_daemon_plugin_deinit,    /* Plugin Deinit */
  0x0100                      /* 1.0 */,
  js_daemon_status_vars,      /* status variables                */
  js_daemon_system_vars,      /* system variables                */
  NULL                        /* config options                  */
}
mysql_declare_plugin_end;

#ifdef __cplusplus
};
#endif
