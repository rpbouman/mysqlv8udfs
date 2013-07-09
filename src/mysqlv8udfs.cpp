#include "stdio.h"
#include "time.h"
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

#define JS_DAEMON_VERSION               "0.0.1";
#define PLUGIN_NAME                     "JS_DAEMON"
#define LOG_LEVEL_ERROR                 "error"
#define LOG_LEVEL_INFO                  "info"
#define LOG_LEVEL_WARN                  "warn"

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
#define MSG_STRING_CONVERSION_FAILED    "<string conversion failed>"

#define MSG_CONNECTION_ALREADY_CLOSED   "Connection already closed."
#define MSG_NOT_ALL_RESULTS_CONSUMED    "Not all results were consumed"
#define MSG_RESULTSET_ALREADY_EXHAUSTED "Resultset already exhausted"
#define MSG_FIELD_INDEX_OUT_OF_RANGE    "Field index out of range"
#define MSG_FIELD_INDEX_MUST_BE_INT     "Field index argument should be an unsigned integer"
#define MSG_EXPECTED_ZERO_ARGUMENTS     "No arguments allowed"
#define MSG_EXPECTED_ONE_ARGUMENT       "Expect at most 1 argument"
#define MSG_ARG_MUST_BE_ARRAY_OR_OBJECT_OR_FUNCTION "Argument must be either an array or an object or a function"
#define MSG_ARG_MUST_BE_STRING          "Argument must be a string"
#define MSG_ARG_MUST_BE_OBJECT          "Argument must be an object"
#define MSG_ARG_MUST_BE_ARRAY           "Argument must be an array"
#define MSG_ARG_MUST_BE_BOOLEAN         "Argument must be a boolean"
#define MSG_FIRST_ARG_MUST_BE_FUNCTION  "First argument must be a function"
#define MSG_SECOND_ARG_MUST_BE_OBJECT   "Second argument must be an object"
#define MSG_HOST_MUST_BE_STRING         "Host must be a string"
#define MSG_USER_MUST_BE_STRING         "User must be a string"
#define MSG_PASSWORD_MUST_BE_STRING     "Password must be a string"
#define MSG_SCHEMA_MUST_BE_STRING       "Schema must be a string"
#define MSG_SOCKET_MUST_BE_STRING       "Socket must be a string"
#define MSG_PORT_MUST_BE_INT            "Port must be an int"
#define MSG_ERR_CONNECTING_TO_MYSQL     "Error connecting to MySQL"
#define MSG_COULD_NOT_ALLOCATE_MYSQL_RESOURCE "Could not allocate MySQL resource"
#define MSG_MEMBER_SQL_MUST_BE_STRING   "Member sql must be a string"
#define MSG_QUERY_ALREADY_PREPARED      "Query already prepared"
#define MSG_QUERY_NOT_YET_DONE          "Query not yet done"
#define MSG_FAILED_TO_ALLOCATE_STATEMENT "Failed to allocate statement"
#define MSG_RESULTS_ALREADY_CONSUMED     "Results already consumed"
#define MSG_FAILED_TO_ALLOCATE_FIELD_EXTRACTORS "Failed to allocate field extractors"

#define LOG_ERR(a) fprintf(stderr, "\n%s", a);

#define INIT_ERROR                      1
#define INIT_SUCCESS                    0

#define PATH_SEPARATOR                  "/"

static v8::Persistent<v8::ObjectTemplate> globalTemplate;
static v8::Persistent<v8::ObjectTemplate> globalTemplateForUDFs;
static v8::Persistent<v8::ObjectTemplate> consoleTemplate;
static v8::Persistent<v8::ObjectTemplate> mysqlTemplate;
static v8::Persistent<v8::ObjectTemplate> mysqlClientTemplate;
static v8::Persistent<v8::ObjectTemplate> mysqlConnectionTemplate;
static v8::Persistent<v8::ObjectTemplate> mysqlQueryTemplate;
static v8::Persistent<v8::ObjectTemplate> mysqlQueryResultSetTemplate;
static v8::Persistent<v8::ObjectTemplate> mysqlQueryResultInfoTemplate;
static v8::Persistent<v8::ObjectTemplate> mysqlExceptionTemplate;

static v8::Persistent<v8::String> str_init;
static v8::Persistent<v8::String> str_deinit;
static v8::Persistent<v8::String> str_udf;
static v8::Persistent<v8::String> str_agg;
static v8::Persistent<v8::String> str_clear;

static v8::Persistent<v8::String> str_mysql;
static v8::Persistent<v8::String> str_console;
static v8::Persistent<v8::String> str_require;

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

static v8::Persistent<v8::String> str_resultset;
static v8::Persistent<v8::String> str_resultinfo;

static v8::Persistent<v8::Integer> int_STRING_RESULT;
static v8::Persistent<v8::Integer> int_INT_RESULT;
static v8::Persistent<v8::Integer> int_DECIMAL_RESULT;
static v8::Persistent<v8::Integer> int_REAL_RESULT;
static v8::Persistent<v8::Integer> int_ROW_RESULT;
static v8::Persistent<v8::Integer> int_NOT_FIXED_DEC;

static v8::Persistent<v8::String> str_charsetnr;
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
static v8::Persistent<v8::String> str_enum;
static v8::Persistent<v8::String> str_set;
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

static v8::Persistent<v8::String> str_sql;
static v8::Persistent<v8::String> str_done;
static v8::Persistent<v8::String> str_rowcount;
static v8::Persistent<v8::String> str_info;

static v8::Persistent<v8::String> str_err_setting_api_constant;
static v8::Persistent<v8::String> str_unsupported_type;
static v8::Persistent<v8::String> str_string_conversion_failed;

static v8::Persistent<v8::String> str_connection_already_closed;
static v8::Persistent<v8::String> str_not_all_results_consumed;
static v8::Persistent<v8::String> str_resultset_already_exhausted;
static v8::Persistent<v8::String> str_field_index_out_of_range;
static v8::Persistent<v8::String> str_field_index_must_be_int;
static v8::Persistent<v8::String> str_expected_zero_arguments;
static v8::Persistent<v8::String> str_expected_one_argument;
static v8::Persistent<v8::String> str_arg_must_be_array_or_object_or_function;
static v8::Persistent<v8::String> str_arg_must_be_string;
static v8::Persistent<v8::String> str_arg_must_be_object;
static v8::Persistent<v8::String> str_arg_must_be_array;
static v8::Persistent<v8::String> str_arg_must_be_boolean;
static v8::Persistent<v8::String> str_first_arg_must_be_function;
static v8::Persistent<v8::String> str_second_arg_must_be_object;
static v8::Persistent<v8::String> str_host_must_be_string;
static v8::Persistent<v8::String> str_user_must_be_string;
static v8::Persistent<v8::String> str_password_must_be_string;
static v8::Persistent<v8::String> str_schema_must_be_string;
static v8::Persistent<v8::String> str_socket_must_be_string;
static v8::Persistent<v8::String> str_port_must_be_int;
static v8::Persistent<v8::String> str_err_connecting_to_mysql;
static v8::Persistent<v8::String> str_could_not_allocate_mysql_resource;
static v8::Persistent<v8::String> str_member_sql_must_be_string;
static v8::Persistent<v8::String> str_query_already_prepared;
static v8::Persistent<v8::String> str_failed_to_allocate_statement;
static v8::Persistent<v8::String> str_failed_to_allocate_field_extractors;
static v8::Persistent<v8::String> str_resultset_already_consumed;
static v8::Persistent<v8::String> str_query_not_yet_done;
static v8::Persistent<v8::String> str_results_already_consumed;

static v8::Persistent<v8::Context> jsDaemonContext;
static v8::HeapStatistics *js_daemon_heap_statistics;

//system variable: holds the directory from where to load js modules.
static char* js_module_path;
MYSQL_SYSVAR_STR(module_path, js_module_path, PLUGIN_VAR_READONLY | PLUGIN_VAR_RQCMDARG, "The directory from where to load javascript modules.", NULL, NULL, "js_modules");

const char* ToCString(const v8::String::Utf8Value& value) {
  return *value ? *value : MSG_STRING_CONVERSION_FAILED;
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

void throwError(v8::Handle<v8::String> message) {
  v8::ThrowException(v8::Exception::Error(message));
}

void setConstant(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info){
  throwError(str_err_setting_api_constant);
}

/*
 * Stuff to implement require (module loading)
 *
*/
typedef struct cached_module CACHED_MODULE;

struct cached_module {
  v8::Persistent<v8::Value> module;
  char *name;
  CACHED_MODULE *next;
};

CACHED_MODULE* module_cache = NULL;
CACHED_MODULE* last_module = module_cache;

CACHED_MODULE* find_module(char *name) {
  LOG_ERR("find module");
  LOG_ERR(name);
  CACHED_MODULE* module = module_cache;
  while (module != NULL && strcmp(name, module->name)) {
    LOG_ERR("looking at module:");
    LOG_ERR(module->name);
    module = module->next;
  }
  return module;
}

CACHED_MODULE* add_module(char *name, v8::Handle<v8::Value> value) {
  LOG_ERR("add module");
  LOG_ERR(name);
  CACHED_MODULE* module = (CACHED_MODULE *)malloc(sizeof(struct cached_module));
  if (module == NULL) return NULL;
  module->name = (char *)malloc(strlen(name) + 1);
  if (module->name == NULL) {
    free(module);
    return NULL;
  }
  strcpy(module->name, name);
  //module->name = name;
  module->module = v8::Persistent<v8::Value>::New(value);
  module->next = NULL;

  if (module_cache == NULL) {
    LOG_ERR("module cache is null, assigning new module.")
    module_cache = module;
  }
  if (last_module != NULL) {
    LOG_ERR("last module is not null, chaining new module.")
    last_module->next = module;
  }

  last_module = module;
  return module;
}

void dispose_module(CACHED_MODULE *module){
  LOG_ERR("dispose module");
  LOG_ERR(module->name);
  module->module.Dispose();
  free(module->name);
  free(module);
}

void clear_module_cache() {
  LOG_ERR("clear module cache");
  CACHED_MODULE* module = module_cache;
  CACHED_MODULE* next;
  while (module != NULL){
    next = module->next;
    module->next = NULL;
    dispose_module(module);
    module = next;
  }
  module_cache = NULL;
  last_module = NULL;
}

FILE * open_script_file(char * script_name){
  LOG_ERR("enter open_script_file");
  int js_module_path_len = strlen(js_module_path);
  int path_sep_len = strlen(PATH_SEPARATOR);
  int script_name_len = strlen(script_name);
  char *file_name = (char *)malloc(js_module_path_len + path_sep_len + script_name_len + 1);
  if (script_name == NULL) {
    LOG_ERR("Could not allocate filename");
    return NULL;
  }
  memcpy(file_name, js_module_path, js_module_path_len);
  memcpy(file_name + js_module_path_len, PATH_SEPARATOR, path_sep_len);
  memcpy(file_name + (js_module_path_len + path_sep_len), script_name, script_name_len);
  file_name[js_module_path_len + path_sep_len + script_name_len] = '\0';
  LOG_ERR(file_name);
  FILE *file = fopen(file_name, "rb");
  free(file_name);
  return file;
}

long get_file_size(FILE *file){
  LOG_ERR("enter get_file_size");
  fseek(file, 0L, SEEK_END);
  long pos = ftell(file);
  rewind(file);
  return pos;
}

char *read_file_contents(FILE *file, long size){
  LOG_ERR("enter read_file_contents");
  long read = 0;
  char *contents = (char *)malloc(size + 1);
  if (contents == NULL) {
    LOG_ERR("require: Error allocating buffer to hold file contents");
    goto ready;
  }

  read = fread(contents, size, 1, file);
  if (read != 1) {
    LOG_ERR("require: Error reading file contents");
    fprintf(stderr, "size: %i; read: %i", (int)size, (int)read);
    free(contents);
    contents = NULL;
  }
  contents[size] = '\0';
ready:
  return contents;
}

char * get_file_contents(FILE *file){
  LOG_ERR("enter get_file_contents");
  char *contents = NULL;
  long pos = get_file_size(file);
  if (pos == -1L) {
    LOG_ERR("require: Error getting file size");
    goto cleanup_file;
  }
  if (pos == 0){
    LOG_ERR("require: file size is zero.");
    goto cleanup_file;
  }
  contents = read_file_contents(file, pos);
cleanup_file:
  fclose(file);
  return contents;
}

my_bool check_script_filename(char *file_name){
  //TODO: checks if this is a valid file name
  //* at a minimum, file name must not break free from module dir.
  //* additional check: extension must be .js?
  return TRUE;
}

v8::Handle<v8::Value> require(const v8::Arguments& args){
  LOG_ERR("Enter require");
  if (args.Length() != 1) {
    LOG_ERR("Whoops, missing argument");
    throwError(str_expected_one_argument);
    return v8::Null();
  }
  if (!args[0]->IsString()) {
    LOG_ERR("Whoops, argument is not a string");
    throwError(str_arg_must_be_string);
    return v8::Null();
  }
  v8::Local<v8::String> arg_file = args[0]->ToString();
  v8::String::AsciiValue ascii(arg_file);
  LOG_ERR("file:");
  LOG_ERR(*ascii);
  CACHED_MODULE *module = find_module(*ascii);
  if (module != NULL) {
    LOG_ERR("Cached module found");
    return module->module;
  }
  if (check_script_filename(*ascii) == FALSE){
    LOG_ERR("oops, script file name is invalid");
    throwError(v8::String::New("require: invalid file name."));
    return v8::Null();
  }
  FILE *file = open_script_file(*ascii);
  if (file == NULL){
    LOG_ERR("oops, file is NULL");
    throwError(v8::String::New("require: Could not open file."));
    return v8::Null();
  }
  char *contents = get_file_contents(file);
  if (contents == NULL) {
    LOG_ERR("oops, contents is NULL");
    throwError(v8::String::New("require: Could not read file."));
    return v8::Null();
  }
  LOG_ERR("script:");
  LOG_ERR(contents);
  v8::Local<v8::String> source = v8::String::New(contents);
  v8::Handle<v8::Script> script = v8::Script::Compile(source);
  if (script.IsEmpty()) {
    LOG_ERR("oops, compilation error");
    free(contents);
    throwError(v8::String::New("require: Error compiling script."));
    return v8::Null();
  }
  v8::Handle<v8::Value> value = script->Run();
  module = add_module(*ascii, value);
  if (module == NULL) {
    LOG_ERR("error caching module");
    throwError(v8::String::New("require: Error caching module."));
    return v8::Null();
  }
  return module->module;
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
  v8::Handle<v8::Value> *arg_values;      //argument values passed to udf functions
  ARG_EXTRACTOR *arg_extractors;          //array of extractor functions to transfer udf arguments to script arguments
  char *result;                          //buffer to hold the string result of executing the script
  unsigned long max_result_length;      //number of bytes allocated for the result buffer.
} V8RES;

//set up arguments.
//Any arguments beyond the initial "script" argument
//are available in a global array called arguments
//this func is called in the init function to create that array.
my_bool setupArguments(V8RES *v8res, UDF_ARGS* args, char *message, my_bool argumentObjects) {
  //allocate room for extractors
  v8res->arg_extractors = (ARG_EXTRACTOR*)malloc(args->arg_count * sizeof(ARG_EXTRACTOR));
  if (v8res->arg_extractors == NULL) {
    strcpy(message, MSG_V8_ALLOCATION_FAILED);
    return INIT_ERROR;
  }
  if (argumentObjects == TRUE) {
    v8res->arg_values = (v8::Handle<v8::Value> *)malloc((args->arg_count - 1) * sizeof(v8::Handle<v8::Value>));
    if (v8res->arg_values == NULL) {
      strcpy(message, MSG_V8_ALLOCATION_FAILED);
      return INIT_ERROR;
    }
  }
  v8::Handle<v8::Value> arg_value;

  v8::Local<v8::Array> arguments = v8::Array::New(args->arg_count - 1);
  if (arguments.IsEmpty()) {
    strcpy(message, MSG_V8_ALLOCATION_FAILED);
    return INIT_ERROR;
  }
  v8res->context->Global()->Set(str_arguments, arguments);
  v8res->arguments = v8::Persistent<v8::Array>::New(arguments);
  v8::Persistent<v8::Integer> int_type;
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
        int_type = int_STRING_RESULT;
        break;
      case INT_RESULT:
        arg_extractor = getIntArgValue;
        int_type = int_INT_RESULT;
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
        int_type = was_decimal ? int_DECIMAL_RESULT : int_REAL_RESULT;
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
    if (argumentObjects == TRUE) {
      v8::Local<v8::Object> argumentObject = v8::Object::New();
      argumentObject->Set(str_name, v8::String::New(args->attributes[i], args->attribute_lengths[i]));
      argumentObject->Set(str_type, int_type);
      argumentObject->Set(str_max_length, v8::Number::New((double)args->lengths[i]));
      argumentObject->Set(str_maybe_null, args->maybe_null[i] == TRUE ? v8::True() : v8::False());
      //determine if this is a constant item
      if (args->args[i] == NULL) {  //value is NULL: either non-constant, or NULL
        if (args->maybe_null[i] == TRUE && args->lengths[i] == 0) { //value maybe null, and max_length is 0 (never not NULL)
          argumentObject->Set(str_const_item, v8::True());
        }
        else {  //value is NULL but max_length not. So this can't be a constant item.
          argumentObject->Set(str_const_item, v8::False());
        }
      }
      else {  //we have a value - this means it's a constant item.
        argumentObject->Set(str_const_item, v8::True());
      }
      v8res->arg_values[i-1] = arg_value;
      argumentObject->Set(str_value, arg_value);
      arg_value = argumentObject;
    }
    v8res->arguments->Set(i - 1, arg_value);
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
MYSQL *getMySQLConnectionInternal(v8::Handle<v8::Object> holder, my_bool throwIfNull = TRUE) {
  MYSQL *mysql = (MYSQL *)v8::Local<v8::External>::Cast(holder->GetInternalField(0))->Value();
  if (mysql == NULL) throwError(str_connection_already_closed);
  return mysql;
}

v8::Handle<v8::Value> mysqlConnectionInternalConnectedGetter(v8::Handle<v8::Object> mysqlConnection);
void weakMysqlConnectionCallback(v8::Persistent<v8::Value> object, void* _mysql) {
  v8::HandleScope handle_scope;
  v8::Local<v8::Object> _object = object->ToObject();
  if (mysqlConnectionInternalConnectedGetter(_object)->IsTrue()) {
    MYSQL *mysql = getMySQLConnectionInternal(_object);
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

void throwMysqlClientException(v8::Handle<v8::Object> object){
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
MYSQL_RES* mysqlQueryResultSetInternalMysqlResGetter(v8::Handle<v8::Object> mysqlQueryResultSet){
  return (MYSQL_RES *)v8::Local<v8::External>::Cast(mysqlQueryResultSet->GetInternalField(0))->Value();
}

v8::Handle<v8::Value> msyqlQueryResultSetInternalDoneGetter(v8::Handle<v8::Object> mysqlQueryResultSet){
  return mysqlQueryResultSet->GetInternalField(1);
}

void cleanupMysqlQueryResultSet(v8::Handle<v8::Object> mysqlQueryResultSet){
  MYSQL_RES* mysql_res = mysqlQueryResultSetInternalMysqlResGetter(mysqlQueryResultSet);
  if (mysql_res == NULL) return;
  //exhaust the result set.
  while (mysql_fetch_row(mysql_res));
  //free the result
  mysql_free_result(mysql_res);
  //null the pointer
  mysqlQueryResultSet->SetInternalField(0, v8::External::New(NULL));
}

void msyqlQueryResultSetInternalDoneSetter(v8::Handle<v8::Object> mysqlQueryResultSet, my_bool value){
  //set the actual field
  mysqlQueryResultSet->SetInternalField(1, value ? v8::True() : v8::False());
  //if (value == TRUE) {
  //  cleanupMysqlQueryResultSet(mysqlQueryResultSet);
  //}
}

void mysqlQueryResultSetDoneSetter(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info){
  v8::Local<v8::Object> mysqlQueryResultSet = info.Holder();
  if (value == msyqlQueryResultSetInternalDoneGetter(mysqlQueryResultSet)) return;
  if (value->IsFalse()) {
    throwError(str_resultset_already_exhausted);
    return;
  }
  cleanupMysqlQueryResultSet(mysqlQueryResultSet);
  msyqlQueryResultSetInternalDoneSetter(mysqlQueryResultSet, TRUE);
}

v8::Handle<v8::Value> mysqlQueryResultSetDoneGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  return msyqlQueryResultSetInternalDoneGetter(info.Holder());
}

v8::Handle<v8::Value> msyqlQueryResultSetInternalBufferedGetter(v8::Handle<v8::Object> mysqlQueryResultSet){
  return mysqlQueryResultSet->GetInternalField(2);
}
void msyqlQueryResultSetInternalBufferedSetter(v8::Handle<v8::Object> mysqlQueryResultSet, my_bool value){
  mysqlQueryResultSet->SetInternalField(2, value ? v8::True() : v8::False());
}

v8::Handle<v8::Value> mysqlQueryResultSetBufferedGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  return msyqlQueryResultSetInternalBufferedGetter(info.Holder());
}

v8::Handle<v8::Value> mysqlQueryResultSetFieldCountGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  LOG_ERR("get fieldcount..");
  v8::Handle<v8::Object> mysqlQueryResultSet = info.Holder();
  MYSQL_RES *mysql_res = mysqlQueryResultSetInternalMysqlResGetter(mysqlQueryResultSet);
  if (mysql_res == NULL) {
    throwError(str_resultset_already_exhausted);
    return v8::Null();
  }
  unsigned int fieldCount = mysql_num_fields(mysql_res);
  return v8::Uint32::New(fieldCount);
}

v8::Handle<v8::Value> mysqlQueryResultSetTypeGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info){
  return str_resultset;
}

MYSQL_ROW mysqlQueryResultSetInternalMysqlRowGetter(v8::Handle<v8::Object> mysqlQueryResultSet){
  return (MYSQL_ROW)v8::Local<v8::External>::Cast(mysqlQueryResultSet->GetInternalField(4))->Value();
}

void mysqlQueryResultSetInternalMysqlRowSetter(v8::Handle<v8::Object> mysqlQueryResultSet, MYSQL_ROW mysql_row){
  mysqlQueryResultSet->SetInternalField(4, v8::External::New(mysql_row));
}

typedef v8::Handle<v8::Value> (*FIELD_EXTRACTOR)(const char *value, unsigned long length);

FIELD_EXTRACTOR *mysqlQueryResultSetInternalExtractorsGetter(v8::Handle<v8::Object> mysqlQueryResultSet){
  return (FIELD_EXTRACTOR *)v8::Local<v8::External>::Cast(mysqlQueryResultSet->GetInternalField(5))->Value();
}

v8::Handle<v8::Value> *mysqlQueryResultSetInternalArgsGetter(v8::Handle<v8::Object> mysqlQueryResultSet){
  return (v8::Handle<v8::Value> *)v8::Local<v8::External>::Cast(mysqlQueryResultSet->GetInternalField(6))->Value();
}

void weakMysqlQueryResultSetCallback(v8::Persistent<v8::Value> object, void* _mysql_res) {
  LOG_ERR("Cleaning up weak mysql query result...");
  v8::HandleScope handle_scope;
  v8::Handle<v8::Object> mysqlQueryResultSet = object->ToObject();
  FIELD_EXTRACTOR *field_extractors = mysqlQueryResultSetInternalExtractorsGetter(mysqlQueryResultSet);
  if (field_extractors != NULL) {
    free(field_extractors);
    mysqlQueryResultSet->SetInternalField(5, v8::External::New(NULL));
  }
  v8::Handle<v8::Value> *args = mysqlQueryResultSetInternalArgsGetter(mysqlQueryResultSet);
  if (args != NULL) {
    free(args);
    mysqlQueryResultSet->SetInternalField(6, v8::External::New(NULL));
  }
  if (!msyqlQueryResultSetInternalDoneGetter(mysqlQueryResultSet)->IsTrue()) {
    msyqlQueryResultSetInternalDoneSetter(mysqlQueryResultSet, TRUE);
  }
  cleanupMysqlQueryResultSet(mysqlQueryResultSet);
  object.Dispose();
}

void msyqlQueryInternalDoneSetter(v8::Handle<v8::Object> mysqlQuery, v8::Handle<v8::Value> value);

void mysqlQueryNextResult(v8::Handle<v8::Object> mysqlQuery){
  MYSQL *mysql = getMySQLConnectionInternal(mysqlQuery);
  LOG_ERR("Check for more...");
  my_bool hasMore = mysql_more_results(mysql);
  LOG_ERR(hasMore ? "we have more" : "we don't have more");
  if (!hasMore) {
    msyqlQueryInternalDoneSetter(mysqlQuery, v8::False());
    return;
  }
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

void mysqlQueryResultSetFetch(v8::Handle<v8::Object> mysqlQueryResultSet) {
  MYSQL_RES *mysql_res = mysqlQueryResultSetInternalMysqlResGetter(mysqlQueryResultSet);
  LOG_ERR("Getting a row");
  MYSQL_ROW mysql_row = mysql_fetch_row(mysql_res);
  if (mysql_row != NULL) {
    LOG_ERR("There are more rows still...");
    mysqlQueryResultSetInternalMysqlRowSetter(mysqlQueryResultSet, mysql_row);
    return;
  }
  msyqlQueryResultSetInternalDoneSetter(mysqlQueryResultSet, TRUE);

  mysqlQueryNextResult(mysqlQueryResultSet->GetInternalField(3)->ToObject());
}

v8::Handle<v8::Value> mysqlQueryResultSetField(const v8::Arguments& args) {
  LOG_ERR("Getting field");
  v8::Local<v8::Object> mysqlQueryResultSet = args.Holder()->ToObject();
  MYSQL_RES *mysql_res = mysqlQueryResultSetInternalMysqlResGetter(mysqlQueryResultSet);
  if (mysql_res == NULL) {
    throwError(str_resultset_already_exhausted);
    return v8::Null();
  }

  MYSQL_FIELD *field = NULL;
  switch (args.Length()) {
    case 0: //no argument passed, get the next field.
  LOG_ERR("No args passed");
      field = mysql_fetch_field(mysql_res);
      break;
    case 1: //argument passed.
  LOG_ERR("args passed");
      if (args[0]->IsUint32()) {
        v8::Local<v8::Uint32> uint = args[0]->ToUint32();
        unsigned long index = uint->Value();
        unsigned int fieldcount = mysql_num_fields(mysql_res);
        if (index < 0 || index > fieldcount) {
          throwError(str_field_index_out_of_range);
          return v8::Null();
        }
        field = mysql_fetch_field_direct(mysql_res, index);
      }
      else {
        throwError(str_field_index_out_of_range);
        return v8::Null();
      }
      break;
    default:
      throwError(str_expected_one_argument);
      return v8::Null();
  }
  if (field == NULL) return v8::Null();
  v8::Local<v8::Object> mysqlQueryField = v8::Object::New();
  LOG_ERR("populating field");
  mysqlQueryField->Set(str_name, v8::String::New(field->name));
  mysqlQueryField->Set(str_type, v8::Uint32::New(field->type));
  mysqlQueryField->Set(str_charsetnr, v8::Uint32::New(field->charsetnr));
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
  mysqlQueryField->Set(str_enum, field->flags & ENUM_FLAG ? v8::True() : v8::False());
  mysqlQueryField->Set(str_set, field->flags & SET_FLAG ? v8::True() : v8::False());
  mysqlQueryField->Set(str_numeric, field->flags & NUM_FLAG ? v8::True() : v8::False());
  return mysqlQueryField;
}

v8::Handle<v8::Value> mysqlQueryResultSetRow(const v8::Arguments& args) {
  LOG_ERR("Fetch");
  v8::Local<v8::Object> mysqlQueryResultSet = args.Holder()->ToObject();
  //get the "done" field
  if (msyqlQueryResultSetInternalDoneGetter(mysqlQueryResultSet)->ToBoolean()->Value()) {
    //throwError(str_resultset_already_exhausted);
    return v8::Null();
  }
  v8::Local<v8::Object> row;
  v8::Local<v8::Value> ret;
  switch (args.Length()) {
    case 0: //no argument passed, create a new one.
      LOG_ERR("No arguments");
      row = v8::Array::New();
      break;
    case 1: //argument passed.
      LOG_ERR("1 argument");
      if (args[0]->IsArray()) row = v8::Local<v8::Array>::Cast(args[0]);
      else
      if (args[0]->IsFunction()) {
        row = mysqlQueryResultSet;
      }
      else
      if (args[0]->IsObject()) row = v8::Local<v8::Object>::Cast(args[0]);
      else {
        LOG_ERR("Argument type not supported");
        throwError(str_arg_must_be_array_or_object_or_function);
        return v8::Null();
      }
      break;
    case 2:
      if (!args[0]->IsFunction()) {
        LOG_ERR("Argument type not supported");
        throwError(str_first_arg_must_be_function);
        return v8::Null();
      }
      if (!args[1]->IsObject()){
        LOG_ERR("Argument type not supported");
        throwError(str_second_arg_must_be_object);
        return v8::Null();
      }
      row = args[1]->ToObject();
      break;
    default:
      LOG_ERR("invalid number of arguments");
      throwError(str_expected_one_argument);
      return v8::Null();
  }

  LOG_ERR("get the row");
  //get the row. this should have been pre-fetched.
  MYSQL_ROW mysql_row = mysqlQueryResultSetInternalMysqlRowGetter(mysqlQueryResultSet);

  //fill the array with values.
  LOG_ERR("get the result");
  MYSQL_RES *mysql_res = mysqlQueryResultSetInternalMysqlResGetter(mysqlQueryResultSet);
  unsigned int i, fieldcount = mysql_num_fields(mysql_res);
  unsigned long *lengths = mysql_fetch_lengths(mysql_res);
  LOG_ERR("get the field extractors");
  FIELD_EXTRACTOR *field_extractors = mysqlQueryResultSetInternalExtractorsGetter(mysqlQueryResultSet);
  if (args[0]->IsFunction()){
    LOG_ERR("Call a function");
    v8::Local<v8::Function> callback = v8::Local<v8::Function>::Cast(args[0]);
    v8::Handle<v8::Value> *_args = mysqlQueryResultSetInternalArgsGetter(mysqlQueryResultSet);
    for (i = 0; i < fieldcount; i++) {
      _args[i] = field_extractors[i](mysql_row[i], lengths[i]);
    }
    ret = callback->Call(row, fieldcount, _args);
  }
  else
  if (row->IsArray()) {
    LOG_ERR("Fill an array");
    for (i = 0; i < fieldcount; i++) {
      row->Set(i, field_extractors[i](mysql_row[i], lengths[i]));
    }
    ret = row;
  }
  else {
    LOG_ERR("Fill an object");
    MYSQL_FIELD* fields = mysql_fetch_fields(mysql_res);
    for (i = 0; i < fieldcount; i++) {
      row->Set(v8::String::New(fields[i].name), field_extractors[i](mysql_row[i], lengths[i]));
    }
    ret = row;
  }
  //fetch the next row. This automatically sets the done flag.
  mysqlQueryResultSetFetch(mysqlQueryResultSet);
  LOG_ERR("Fetch ready.");
  return ret;
}

v8::Persistent<v8::ObjectTemplate> createMysqlQueryResultSetTemplate(){
  v8::Handle<v8::ObjectTemplate> _mysqlQueryResultSetTemplate = v8::ObjectTemplate::New();
  //0 is the result, 1 is done flag, 2 is buffered flag, 3 is query, 4 is the current row,
  //5 is the extractor array, 6 is a handle array to pass to the row callback function
  _mysqlQueryResultSetTemplate->SetInternalFieldCount(7);
  _mysqlQueryResultSetTemplate->SetAccessor(str_done, mysqlQueryResultSetDoneGetter, mysqlQueryResultSetDoneSetter);
  _mysqlQueryResultSetTemplate->SetAccessor(str_type, mysqlQueryResultSetTypeGetter, setConstant);
  _mysqlQueryResultSetTemplate->SetAccessor(v8::String::New("fieldCount"), mysqlQueryResultSetFieldCountGetter, setConstant);
  _mysqlQueryResultSetTemplate->SetAccessor(v8::String::New("buffered"), mysqlQueryResultSetBufferedGetter, setConstant);
  _mysqlQueryResultSetTemplate->Set(v8::String::New("field"), v8::FunctionTemplate::New(mysqlQueryResultSetField));
  _mysqlQueryResultSetTemplate->Set(v8::String::New("row"), v8::FunctionTemplate::New(mysqlQueryResultSetRow));
  return v8::Persistent<v8::ObjectTemplate>::New(_mysqlQueryResultSetTemplate);
}

v8::Handle<v8::Value> mysqlQueryResultInfoTypeGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info){
  return str_resultinfo;
}

v8::Handle<v8::Value> mysqlQueryResultInfoDoneGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info){
  return v8::True();
}

v8::Persistent<v8::ObjectTemplate> createMysqlQueryResultInfoTemplate(){
  v8::Handle<v8::ObjectTemplate> _mysqlQueryResultInfoTemplate = v8::ObjectTemplate::New();
  _mysqlQueryResultInfoTemplate->SetAccessor(str_done, mysqlQueryResultInfoDoneGetter, setConstant);
  _mysqlQueryResultInfoTemplate->SetAccessor(str_type, mysqlQueryResultInfoTypeGetter, setConstant);
  return v8::Persistent<v8::ObjectTemplate>::New(_mysqlQueryResultInfoTemplate);
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
  throwError(str_not_all_results_consumed);
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

my_bool createImmediateQueryResultSetExtractors(v8::Local<v8::Object> mysqlQueryResultSet) {
  MYSQL_RES* mysql_res = mysqlQueryResultSetInternalMysqlResGetter(mysqlQueryResultSet);
  unsigned int num_fields = mysql_num_fields(mysql_res);
  FIELD_EXTRACTOR *field_extractors = (FIELD_EXTRACTOR *)malloc(sizeof(FIELD_EXTRACTOR) * num_fields);
  mysqlQueryResultSet->SetInternalField(5, v8::External::New(field_extractors));
  if (field_extractors == NULL) {
    throwError(str_failed_to_allocate_field_extractors);
    return FALSE;
  }
  MYSQL_FIELD *field;
  for (unsigned int i = 0; i < num_fields; i++) {
    field = mysql_fetch_field_direct(mysql_res, i);
    field_extractors[i] = getFieldExtractor(field);
  }
  return TRUE;
}

v8::Handle<v8::Object> createMysqlImmediateQueryResultInfo(MYSQL *mysql){
  LOG_ERR("creating info result");
  v8::Handle<v8::Object> mysqlImmediateQueryResultInfo = mysqlQueryResultInfoTemplate->NewInstance();

  double affected_rows = (double)mysql_affected_rows(mysql);
  mysqlImmediateQueryResultInfo->Set(str_rowcount, v8::Number::New(affected_rows));

  const char *info = mysql_info(mysql);
  LOG_ERR("info");
  LOG_ERR(info);
  const char *delim = " ";

  char *tok = strtok((char *)info, delim);
  while (tok != NULL) {
  LOG_ERR("token");
  LOG_ERR(tok);
    if (strcmp("Records:", tok)) {
      tok = strtok(NULL, delim);
      mysqlImmediateQueryResultInfo->Set(v8::String::New("records"), v8::Number::New(atof(tok)));
    }
    tok = strtok(NULL, delim);
  }

  return mysqlImmediateQueryResultInfo;
}

v8::Handle<v8::Value> mysqlImmediateQueryResult(v8::Local<v8::Object> mysqlQuery, my_bool useOrStore) {
  LOG_ERR("Getting a result. Use or store: ");
  LOG_ERR(useOrStore ? "store" : "use");
  //get the actual result.
  LOG_ERR("Get connection");
  MYSQL *mysql = getMySQLConnectionInternal(mysqlQuery);
  LOG_ERR("Get result");
  MYSQL_RES *mysql_res = useOrStore ? mysql_store_result(mysql) : mysql_use_result(mysql);

  if (mysql_res == NULL) {
    LOG_ERR("result is null");
    if (mysql_errno(mysql) != 0) {
      LOG_ERR("oops, error");
      throwMysqlClientException(mysqlQuery);
      return v8::Null();
    }
    //not the kind of query that has a result.
    //TODO: return a special result object with the number of affected rows.
    v8::Handle<v8::Value> mysqlImmediateQueryResultInfo = createMysqlImmediateQueryResultInfo(mysql);
    mysqlQueryNextResult(mysqlQuery);
    return mysqlImmediateQueryResultInfo;
  }

  v8::Local<v8::Object> mysqlQueryResultSet = mysqlQueryResultSetTemplate->NewInstance();
  mysqlQueryResultSet->SetInternalField(0, v8::External::New(mysql_res));
  mysqlQueryResultSet->SetInternalField(6, v8::External::New(NULL));
  //mark this result dependent upon the holder.
  //This prevents the holder from being cleaned up before the result.
  mysqlQueryResultSet->SetInternalField(3, mysqlQuery);

  //set the result's done flag
  msyqlQueryResultSetInternalDoneSetter(mysqlQueryResultSet, mysql_res == NULL);
  if (mysql_res != NULL) {
    mysqlQueryResultSetFetch(mysqlQueryResultSet);
  }

  //set the result's buffered flag.
  msyqlQueryResultSetInternalBufferedSetter(mysqlQueryResultSet, useOrStore);

  if (createImmediateQueryResultSetExtractors(mysqlQueryResultSet) == FALSE) return v8::Null();
  unsigned int num_fields = mysql_num_fields(mysql_res);
  v8::Handle<v8::Value> *args = (v8::Handle<v8::Value> *)malloc(sizeof(v8::Handle<v8::Value>) * num_fields);
  if (args == NULL) {
    throwError(str_failed_to_allocate_field_extractors);
    return v8::Null();
  }
  mysqlQueryResultSet->SetInternalField(6, v8::External::New(args));

  //make the result persistent and set weak hooks.
  v8::Persistent<v8::Object> persistentMysqlQueryResultSet= v8::Persistent<v8::Object>::New(mysqlQueryResultSet);
  persistentMysqlQueryResultSet.MakeWeak(mysql_res, weakMysqlQueryResultSetCallback);

  LOG_ERR("Done getting a result");
  return persistentMysqlQueryResultSet;
}

//TODO: lots of stuff, currently we don't have prepared statement interface covered.
v8::Handle<v8::Value> mysqlPreparedQueryResult(v8::Local<v8::Object> mysqlQuery, my_bool useOrStore) {
  v8::Persistent<v8::Object> persistentMysqlQueryResultSet;
  MYSQL_STMT *mysql_stmt = mysqlQueryInternalMysqlStmtGetter(mysqlQuery);
  if (useOrStore == TRUE) {
    int result = mysql_stmt_store_result(mysql_stmt);
    if (result != 0) {
      throwMysqlStmtException(mysqlQuery);
    }
  }
  return persistentMysqlQueryResultSet;
}

v8::Handle<v8::Value> mysqlQueryResult(const v8::Arguments& args) {
  //holder is the query object on which the result method was called.
  v8::Local<v8::Object> mysqlQuery = args.Holder()->ToObject();
  //if the query's done flag is true, we bail out.
  v8::Handle<v8::Boolean> queryDone = msyqlQueryInternalDoneGetter(mysqlQuery);
  if (queryDone->IsTrue()) {
    throwError(str_results_already_consumed);
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
        throwError(str_arg_must_be_boolean);
        return v8::Null();
      }
      _useOrStore = arg->ToBoolean()->Value() ? TRUE : FALSE;
      break;
    }
    default: {
      throwError(str_expected_one_argument);
      return v8::Null();
    }
  }

  v8::Handle<v8::Value> mysqlQueryResult;
  //TODO: properly handle diff. cases prepared / immediate
  if (mysqlQueryCheckPrepared(mysqlQuery) == TRUE) {
    mysqlQueryResult = mysqlPreparedQueryResult(mysqlQuery, _useOrStore);
  }
  else {
    mysqlQueryResult = mysqlImmediateQueryResult(mysqlQuery, _useOrStore);
  }
  return mysqlQueryResult;
}

v8::Handle<v8::Value> mysqlQueryExecute(const v8::Arguments& args) {
  LOG_ERR("Executing query");
  v8::Local<v8::Object> mysqlQuery = args.Holder()->ToObject();
  //check the done field. if it's not true we can't execute.
  //beware: done maybe True, False, or Null
  if (!checkDone(mysqlQuery)) {
    throwError(str_query_not_yet_done);
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
        throwError(str_arg_must_be_array);
        return v8::Null();
      }
      //for now we simply exit. If prepared we should execute with these parameters.
      throwError(v8::String::New("Parameter passing not (yet) supported."));
      return v8::Null();
    }
    default: {
      throwError(str_expected_one_argument);
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
    v8::Local<v8::Value> _sql = mysqlQuery->Get(str_sql);
    if (!_sql->IsString()) {
      throwError(str_member_sql_must_be_string);
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
    throwError(str_query_already_prepared);
    return v8::False();
  }
  MYSQL *mysql = getMySQLConnectionInternal(mysqlQuery);
  MYSQL_STMT *mysql_stmt = mysql_stmt_init(mysql);
  if (mysql_stmt == NULL) {
    throwError(str_failed_to_allocate_statement);
    return v8::False();
  }
  v8::String::AsciiValue ascii(mysqlQuery->Get(str_sql)->ToString());

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
  _mysqlQueryTemplate->SetAccessor(str_done, mysqlQueryDoneGetter, setConstant);
  _mysqlQueryTemplate->SetAccessor(v8::String::New("prepared"), mysqlQueryPreparedGetter, setConstant);
  _mysqlQueryTemplate->SetAccessor(v8::String::New("paramCount"), mysqlQueryParamCountGetter, setConstant);
  _mysqlQueryTemplate->Set(v8::String::New("execute"), v8::FunctionTemplate::New(mysqlQueryExecute));
  _mysqlQueryTemplate->Set(v8::String::New("result"), v8::FunctionTemplate::New(mysqlQueryResult));
  _mysqlQueryTemplate->Set(v8::String::New("prepare"), v8::FunctionTemplate::New(mysqlQueryPrepare));
  return v8::Persistent<v8::ObjectTemplate>::New(_mysqlQueryTemplate);
}

v8::Handle<v8::Value> createMysqlQuery(const v8::Arguments& args) {
  if (args.Length() != 1) {
    throwError(str_expected_one_argument);
    return v8::Null();
  }
  v8::Local<v8::Value> arg = args[0];
  if (!arg->IsString()) {
    throwError(str_arg_must_be_string);
    return v8::Null();
  }
  //holder is the mysql client object.
  v8::Local<v8::Object> holder = args.Holder()->ToObject();
  MYSQL *mysql = getMySQLConnectionInternal(holder);

  //make a new query object
  v8::Local<v8::Object> mysqlQuery = mysqlQueryTemplate->NewInstance();
  mysqlQuery->SetInternalField(0, v8::External::New(mysql));
  //False = More results. Null = ready to get first result. True = done.
  msyqlQueryInternalDoneSetter(mysqlQuery, v8::True());
  //mark the query dependent upon the client object.
  mysqlQuery->SetInternalField(2, holder);
  //mark the query as not prepared
  mysqlQuery->SetInternalField(3, v8::False());
  //set the stmt field to null
  mysqlQuery->SetInternalField(4, v8::Null());
  mysqlQuery->Set(str_sql, arg->ToString());
  //deliver the query object.
  v8::Persistent<v8::Object> persistentMysqlQuery = v8::Persistent<v8::Object>::New(mysqlQuery);
  persistentMysqlQuery.MakeWeak(mysql, weakMysqlQueryCallback);
  return persistentMysqlQuery;
}

/**
 *  MySQL bindings: Connection
 *
 */
v8::Handle<v8::Value> mysqlConnectionInternalConnectedGetter(v8::Handle<v8::Object> mysqlConnection){
  return mysqlConnection->GetInternalField(1);
}

my_bool checkConnected(v8::Handle<v8::Object> mysqlConnection){
  if (mysqlConnectionInternalConnectedGetter(mysqlConnection)->IsTrue()) return TRUE;
  throwError(str_connection_already_closed);
  return FALSE;
}

v8::Handle<v8::Value> mysqlConnectionConnectedGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  return mysqlConnectionInternalConnectedGetter(info.Holder());
}

v8::Handle<v8::Value> mysqlConnectionClose(const v8::Arguments& args) {
  v8::Local<v8::Object> holder = args.Holder();
  if (mysqlConnectionInternalConnectedGetter(holder)->IsFalse()) return v8::False();
  MYSQL *mysql = getMySQLConnectionInternal(holder, FALSE);
  if (mysql == NULL) return v8::False();
  mysql_close(mysql);
  holder->SetInternalField(0, v8::External::New(NULL));
  holder->SetInternalField(1, v8::False());
  return v8::True();
}

v8::Handle<v8::Value> mysqlConnectionCommit(const v8::Arguments& args) {
  v8::Local<v8::Object> holder = args.Holder();
  if (checkConnected(holder) == FALSE) return v8::False();
  MYSQL *mysql = getMySQLConnectionInternal(holder);
  if (mysql_commit(mysql)) {
    throwMysqlClientException(holder);
    return v8::Null();
  }
  return v8::True();
}

v8::Handle<v8::Value> mysqlConnectionRollback(const v8::Arguments& args) {
  v8::Local<v8::Object> holder = args.Holder();
  if (checkConnected(holder) == FALSE) return v8::False();
  MYSQL *mysql = getMySQLConnectionInternal(holder);
  if (mysql_rollback(mysql)) {
    throwMysqlClientException(holder);
    return v8::Null();
  }
  return v8::True();
}

v8::Handle<v8::Value> mysqlConnectionSetAutocommit(const v8::Arguments& args) {
  v8::Local<v8::Object> holder = args.Holder();
  if (checkConnected(holder) == FALSE) return v8::False();
  if (args.Length() != 1) {
    throwError(str_expected_one_argument);
    return v8::False();
  }
  my_bool mode = args[0]->IsTrue() ? TRUE : FALSE;
  MYSQL *mysql = getMySQLConnectionInternal(holder);
  if (mysql_autocommit(mysql, mode)) {
    throwMysqlClientException(holder);
    return v8::Null();
  }
  return v8::True();
}

v8::Handle<v8::Value> mysqlConnectionHostInfoGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  v8::Local<v8::Object> holder = info.Holder();
  if (checkConnected(holder) == FALSE) return v8::False();
  MYSQL *mysql = getMySQLConnectionInternal(holder);
  return v8::String::New(mysql_get_host_info(mysql));
}

v8::Handle<v8::Value> mysqlConnectionProtocolInfoGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  v8::Local<v8::Object> holder = info.Holder();
  if (checkConnected(holder) == FALSE) return v8::False();
  MYSQL *mysql = getMySQLConnectionInternal(holder);
  return v8::Integer::New(mysql_get_proto_info(mysql));
}

v8::Handle<v8::Value> mysqlConnectionServerInfoGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  v8::Local<v8::Object> holder = info.Holder();
  if (checkConnected(holder) == FALSE) return v8::False();
  MYSQL *mysql = getMySQLConnectionInternal(holder);
  return v8::String::New(mysql_get_server_info(mysql));
}

v8::Handle<v8::Value> mysqlConnectionAffectedRowsGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  v8::Local<v8::Object> holder = info.Holder();
  if (checkConnected(holder) == FALSE) return v8::False();
  MYSQL *mysql = getMySQLConnectionInternal(holder);
  my_ulonglong result = mysql_affected_rows(mysql);
  if (result == (my_ulonglong)~0) {
    throwMysqlClientException(info.Holder());
    return v8::Null();
  }
  return v8::Number::New((double)result);
}

v8::Handle<v8::Value> mysqlConnectionWarningsGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  v8::Local<v8::Object> holder = info.Holder();
  if (checkConnected(holder) == FALSE) return v8::False();
  MYSQL *mysql = getMySQLConnectionInternal(holder);
  return v8::Integer::New(mysql_warning_count(mysql));
}

v8::Handle<v8::Value> mysqlConnectionInsertIdGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  v8::Local<v8::Object> holder = info.Holder();
  if (checkConnected(holder) == FALSE) return v8::False();
  MYSQL *mysql = getMySQLConnectionInternal(holder);
  return v8::Number::New((double)mysql_insert_id(mysql));
}

v8::Handle<v8::Value> mysqlConnectionStatGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  v8::Local<v8::Object> holder = info.Holder();
  if (checkConnected(holder) == FALSE) return v8::False();
  MYSQL *mysql = getMySQLConnectionInternal(holder);
  const char *stat = mysql_stat(mysql);
  if (stat == NULL) {
    throwMysqlClientException(holder);
    return v8::Null();
  }
  return v8::String::New(stat);
}

v8::Handle<v8::Value> mysqlConnectionCharsetGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
  v8::Local<v8::Object> holder = info.Holder();
  if (checkConnected(holder) == FALSE) return v8::False();
  MYSQL *mysql = getMySQLConnectionInternal(holder);
  return v8::String::New(mysql_character_set_name(mysql));
}

void mysqlConnectionCharsetSetter(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info) {
  v8::Local<v8::Object> holder = info.Holder();
  if (checkConnected(holder) == FALSE) return;
  MYSQL *mysql = getMySQLConnectionInternal(holder);
  v8::String::AsciiValue ascii(value);
  if (mysql_set_character_set(mysql, *ascii)) {
    throwMysqlClientException(holder);
  }
}

v8::Persistent<v8::ObjectTemplate> createMysqlConnectionTemplate(){
  v8::Handle<v8::ObjectTemplate> _mysqlConnectionTemplate = v8::ObjectTemplate::New();
  //first field is MYSQL * pointer, second field is closed flag.
  _mysqlConnectionTemplate->SetInternalFieldCount(2);
  _mysqlConnectionTemplate->Set(v8::String::New("close"), v8::FunctionTemplate::New(mysqlConnectionClose));
  _mysqlConnectionTemplate->Set(v8::String::New("commit"), v8::FunctionTemplate::New(mysqlConnectionCommit));
  _mysqlConnectionTemplate->Set(v8::String::New("rollback"), v8::FunctionTemplate::New(mysqlConnectionRollback));
  _mysqlConnectionTemplate->Set(v8::String::New("query"), v8::FunctionTemplate::New(createMysqlQuery));
  _mysqlConnectionTemplate->Set(v8::String::New("setAutoCommit"), v8::FunctionTemplate::New(mysqlConnectionSetAutocommit));

  //TODO: probably should call affectedRows automatically inside the query object so each query object maintains their own info.
  _mysqlConnectionTemplate->SetAccessor(v8::String::New("affectedRows"), mysqlConnectionAffectedRowsGetter, setConstant);

  _mysqlConnectionTemplate->SetAccessor(v8::String::New("charset"), mysqlConnectionCharsetGetter, mysqlConnectionCharsetSetter);
  _mysqlConnectionTemplate->SetAccessor(v8::String::New("connected"), mysqlConnectionConnectedGetter, setConstant);
  _mysqlConnectionTemplate->SetAccessor(v8::String::New("hostInfo"), mysqlConnectionHostInfoGetter, setConstant);
  _mysqlConnectionTemplate->SetAccessor(v8::String::New("insertId"), mysqlConnectionInsertIdGetter, setConstant);
  _mysqlConnectionTemplate->SetAccessor(v8::String::New("protocolVersion"),  mysqlConnectionProtocolInfoGetter, setConstant);
  _mysqlConnectionTemplate->SetAccessor(v8::String::New("serverVersion"), mysqlConnectionServerInfoGetter, setConstant);
  _mysqlConnectionTemplate->SetAccessor(v8::String::New("statistics"), mysqlConnectionStatGetter, setConstant);
  _mysqlConnectionTemplate->SetAccessor(v8::String::New("warnings"), mysqlConnectionWarningsGetter, setConstant);
  return v8::Persistent<v8::ObjectTemplate>::New(_mysqlConnectionTemplate);
}

/**
 *  MySQL bindings: Client
 *
 */
my_bool getStringFromObject(v8::Local<v8::Object> argObject, v8::Persistent<v8::String> key, char *buffer, v8::Persistent<v8::String> error) {
  v8::Local<v8::Value> value;
  if (argObject->Has(key)) {
    value = argObject->Get(key);
    if (value->IsString()) {
      v8::String::AsciiValue ascii(value->ToString());
      strcpy(buffer, *ascii);
    }
    else {
      throwError(error);
      return FALSE;
    }
  }
  return TRUE;
}

my_bool getUint32FromObject(v8::Local<v8::Object> argObject, v8::Persistent<v8::String> key, unsigned short *buffer, v8::Persistent<v8::String> error){
  v8::Local<v8::Value> value;
  if (argObject->Has(key)) {
    value = argObject->Get(key);
    if (value->IsUint32()) {
      *buffer = value->ToUint32()->Value();
    }
    else {
      throwError(error);
      return FALSE;
    }
  }
  return TRUE;
}

my_bool getUint64FromObject(v8::Local<v8::Object> argObject, v8::Persistent<v8::String> key, unsigned long *buffer, v8::Persistent<v8::String> error){
  v8::Local<v8::Value> value;
  if (argObject->Has(key)) {
    value = argObject->Get(key);
    if (value->IsNumber()) {
      *buffer = value->ToInteger()->Value();
    }
    else {
      throwError(error);
      return FALSE;
    }
  }
  return TRUE;
}

v8::Handle<v8::Value> mysqlClientConnect(const v8::Arguments& args) {
  //TODO: create a real mysql connection
  MYSQL *mysql = mysql_init(NULL);
  if (mysql == NULL) {
    LOG_ERR(MSG_COULD_NOT_ALLOCATE_MYSQL_RESOURCE);
    throwError(str_could_not_allocate_mysql_resource);
    return v8::Null();
  }

  v8::HandleScope handle_scope;
  char host[64]; strcpy(host, LOCAL_HOST);  //LOCAL_HOST from mysql_com.h
  char user[16]; strcpy(user, "");
  char password[16]; strcpy(password, "");
  char schema[64]; strcpy(schema, "");
  unsigned short port = MYSQL_PORT;
  char socket[128]; strcpy(socket, "");
  unsigned long flags = CLIENT_IGNORE_SPACE | CLIENT_MULTI_STATEMENTS | CLIENT_MULTI_RESULTS;

  if (args.Length()) {
    v8::Local<v8::Value> arg = args[0];
    if (!arg->IsObject()) {
      throwError(str_arg_must_be_object);
      return v8::Null();
    }
    v8::Local<v8::Object> argObject = arg->ToObject();
    v8::Local<v8::String> key;

    if (getStringFromObject(argObject, str_host, host, str_host_must_be_string) == FALSE) return v8::Null();
    if (getStringFromObject(argObject, str_user, user, str_user_must_be_string) == FALSE) return v8::Null();
    if (getStringFromObject(argObject, str_password, password, str_password_must_be_string) == FALSE) return v8::Null();
    if (getStringFromObject(argObject, str_schema, schema, str_schema_must_be_string) == FALSE) return v8::Null();
    if (getStringFromObject(argObject, str_socket, socket, str_socket_must_be_string) == FALSE) return v8::Null();
    if (getUint32FromObject(argObject, str_port, &port, str_port_must_be_int) == FALSE) return v8::Null();
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
    throwError(str_err_connecting_to_mysql);
    return v8::Null();
  }

  v8::Local<v8::Object> mysqlConnection = mysqlConnectionTemplate->NewInstance();
  mysqlConnection->SetInternalField(0, v8::External::New(mysql));
  //connected flag.
  mysqlConnection->SetInternalField(1, v8::True());

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
 *  MySQL bindings: mysql "namespace"
 *
 */

v8::Persistent<v8::ObjectTemplate> createMysqlTemplate(){
  v8::Handle<v8::ObjectTemplate> _mysqlTemplate = v8::ObjectTemplate::New();
  _mysqlTemplate->Set(v8::String::New("client"), mysqlClientTemplate->NewInstance());
  v8::Handle<v8::Object> mysqlTypes = v8::Object::New();
  mysqlTypes->Set(MYSQL_TYPE_TINY, v8::String::New("tinyint"));
  mysqlTypes->Set(MYSQL_TYPE_SHORT, v8::String::New("smallint"));
  mysqlTypes->Set(MYSQL_TYPE_LONG, v8::String::New("int"));
  mysqlTypes->Set(MYSQL_TYPE_INT24, v8::String::New("mediumint"));
  mysqlTypes->Set(MYSQL_TYPE_LONGLONG, v8::String::New("bigint"));
  mysqlTypes->Set(MYSQL_TYPE_DECIMAL, v8::String::New("decimal"));
  mysqlTypes->Set(MYSQL_TYPE_NEWDECIMAL, v8::String::New("decimal"));
  mysqlTypes->Set(MYSQL_TYPE_FLOAT, v8::String::New("float"));
  mysqlTypes->Set(MYSQL_TYPE_DOUBLE, v8::String::New("double"));
  mysqlTypes->Set(MYSQL_TYPE_BIT, v8::String::New("bit"));
  mysqlTypes->Set(MYSQL_TYPE_TIMESTAMP, v8::String::New("timestamp"));
  mysqlTypes->Set(MYSQL_TYPE_DATE, v8::String::New("date"));
  mysqlTypes->Set(MYSQL_TYPE_TIME, v8::String::New("time"));
  mysqlTypes->Set(MYSQL_TYPE_DATETIME, v8::String::New("datetime"));
  mysqlTypes->Set(MYSQL_TYPE_YEAR, v8::String::New("year"));
  mysqlTypes->Set(MYSQL_TYPE_STRING, v8::String::New("string"));
  mysqlTypes->Set(MYSQL_TYPE_VAR_STRING, v8::String::New("varstring"));
  mysqlTypes->Set(MYSQL_TYPE_BLOB, v8::String::New("blob"));
  mysqlTypes->Set(MYSQL_TYPE_SET, v8::String::New("set"));
  mysqlTypes->Set(MYSQL_TYPE_ENUM, v8::String::New("enum"));
  mysqlTypes->Set(MYSQL_TYPE_GEOMETRY, v8::String::New("geometry"));
  mysqlTypes->Set(MYSQL_TYPE_NULL, v8::String::New("null"));
  _mysqlTemplate->Set(v8::String::New("column_types"), mysqlTypes);
  return v8::Persistent<v8::ObjectTemplate>::New(_mysqlTemplate);
}

/**
 *  Global Object
 */
 /**
 *
 *  Wrapping useful udf constants
 *
 */
v8::Handle<v8::Value> getStringResultConstant(v8::Local<v8::String> property, const v8::AccessorInfo& info){
  return int_STRING_RESULT;
}

v8::Handle<v8::Value> getRealResultConstant(v8::Local<v8::String> property, const v8::AccessorInfo& info){
  return int_REAL_RESULT;
}

v8::Handle<v8::Value> getIntResultConstant(v8::Local<v8::String> property, const v8::AccessorInfo& info){
  return int_INT_RESULT;
}

v8::Handle<v8::Value> getRowResultConstant(v8::Local<v8::String> property, const v8::AccessorInfo& info){
  return int_ROW_RESULT;
}

v8::Handle<v8::Value> getDecimalResultConstant(v8::Local<v8::String> property, const v8::AccessorInfo& info){
  return int_DECIMAL_RESULT;
}

v8::Handle<v8::Value> getNotFixedDecConstant(v8::Local<v8::String> property, const v8::AccessorInfo& info){
  return int_NOT_FIXED_DEC;
}

void addBuiltInGlobals(v8::Handle<v8::ObjectTemplate> _template){
  _template->Set(str_console, consoleTemplate->NewInstance());
  _template->Set(str_mysql, mysqlTemplate->NewInstance());
  _template->Set(str_require, v8::FunctionTemplate::New(require));
}

v8::Persistent<v8::ObjectTemplate> createGlobalTemplate(){
  v8::Handle<v8::ObjectTemplate> _template = v8::ObjectTemplate::New();
  _template->SetInternalFieldCount(1);
  addBuiltInGlobals(_template);
  return v8::Persistent<v8::ObjectTemplate>::New(_template);
}

v8::Persistent<v8::ObjectTemplate> createGlobalTemplateForUDFs(){
  v8::Handle<v8::ObjectTemplate> _template = v8::ObjectTemplate::New();
  _template->SetInternalFieldCount(1);
  _template->SetAccessor(str_STRING_RESULT, getStringResultConstant, setConstant);
  _template->SetAccessor(str_REAL_RESULT, getRealResultConstant, setConstant);
  _template->SetAccessor(str_INT_RESULT, getIntResultConstant, setConstant);
  _template->SetAccessor(str_ROW_RESULT, getRowResultConstant, setConstant);
  _template->SetAccessor(str_DECIMAL_RESULT, getDecimalResultConstant, setConstant);
  _template->SetAccessor(str_NOT_FIXED_DEC, getNotFixedDecConstant, setConstant);
  addBuiltInGlobals(_template);
  return v8::Persistent<v8::ObjectTemplate>::New(_template);
}

v8::Handle<v8::Value> log(const char *kind, const v8::Arguments& args){
  if (kind != NULL) {
    time_t timer;
    time(&timer);
    struct tm *timeinfo;
    timeinfo = localtime(&timer);

    fprintf(stderr, "%i-%s%i-%s%i %s%i:%s%i:%s%i %s [%s]: ",
      1900+timeinfo->tm_year,
      timeinfo->tm_mon  <  9 ? "0" : "",
      1+timeinfo->tm_mon,
      timeinfo->tm_mday < 10 ? "0" : "",
      timeinfo->tm_mday,
      timeinfo->tm_hour < 10 ? "0" : "",
      timeinfo->tm_hour,
      timeinfo->tm_min  < 10 ? "0" : "",
      timeinfo->tm_min,
      timeinfo->tm_sec  < 10 ? "0" : "",
      timeinfo->tm_sec,
      PLUGIN_NAME,
      kind
    );
  }

  unsigned long argc = args.Length();
  unsigned long i;
  v8::Local<v8::String> arg;
  for (i = 0; i < argc; i++) {
    arg = args[i]->ToString();
    v8::String::AsciiValue ascii(arg);
    fprintf(stderr, "%s", *ascii);
  }
  fprintf(stderr, "%s", "\n");
  return v8::Null();
}

v8::Handle<v8::Value> consoleError(const v8::Arguments& args) {
  return log(LOG_LEVEL_ERROR, args);
}

v8::Handle<v8::Value> consoleWarn(const v8::Arguments& args) {
  return log(LOG_LEVEL_WARN, args);
}

v8::Handle<v8::Value> consoleInfo(const v8::Arguments& args) {
  return log(LOG_LEVEL_INFO, args);
}

v8::Handle<v8::Value> consoleLog(const v8::Arguments& args) {
  return log(NULL, args);
}
/**
 *  Console Object
 */
v8::Persistent<v8::ObjectTemplate> createConsoleTemplate(){
  v8::Handle<v8::ObjectTemplate> _consoleTemplate = v8::ObjectTemplate::New();
  _consoleTemplate->Set(v8::String::New(LOG_LEVEL_ERROR), v8::FunctionTemplate::New(consoleError));
  _consoleTemplate->Set(v8::String::New(LOG_LEVEL_INFO), v8::FunctionTemplate::New(consoleInfo));
  _consoleTemplate->Set(v8::String::New(LOG_LEVEL_WARN), v8::FunctionTemplate::New(consoleWarn));
  _consoleTemplate->Set(v8::String::New("log"), v8::FunctionTemplate::New(consoleLog));
  return v8::Persistent<v8::ObjectTemplate>::New(_consoleTemplate);
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

int status_var_version(MYSQL_THD thd, struct st_mysql_show_var *var, char *buff){
  var->type = SHOW_CHAR;
  var->value = (char *)JS_DAEMON_VERSION;
  return 0;
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
  *buff = (int)js_daemon_heap_statistics->total_heap_size_executable();
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
  {"js_daemon_version", (char *)&status_var_version, SHOW_FUNC},
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
  MYSQL_SYSVAR(module_path),
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
  if (setupArguments(v8res, args, message, FALSE) == INIT_ERROR) return INIT_ERROR;

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
  if (js_check_arguments(args, message) == INIT_ERROR) return INIT_ERROR;
  if (js_alloc_resources(initid, args, message) == INIT_ERROR) return INIT_ERROR;
  js_set_initid_defaults(initid);

  //v8 introductory voodoo incantations
  v8::Locker locker;
  v8::HandleScope handle_scope;

  //set up a context
  V8RES *v8res = (V8RES *)initid->ptr;
  v8res->context = v8::Context::New(NULL, globalTemplateForUDFs);
  if (v8res->context.IsEmpty()) {
    strcpy(message, MSG_CREATE_CONTEXT_FAILED);
    return INIT_ERROR;
  }
  v8res->context->Enter();

  //create and initialize arguments array
  if (setupArguments(v8res, args, message, TRUE) == INIT_ERROR) return INIT_ERROR;

  if (js_pre_compile(initid, args, message) == INIT_ERROR) return INIT_ERROR;
  if (v8res->compiled != COMPILED_YES) {
    strcpy(message, MSG_STATIC_SCRIPT_REQUIRED);
    return INIT_ERROR;
  }
  v8::TryCatch try_catch;

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

  member = global->Get(str_udf);
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

  //look if there is an init function, and call it.
  member = global->Get(str_init);
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
  /*
  if (updateArgsFromArgumentObjects(v8res, args) == INIT_ERROR) {
    strcpy(message, MSG_UNSUPPORTED_TYPE);
    v8res->context->Exit();
    return INIT_ERROR;
  }
  */
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

  member = global->Get(str_clear);
  if (!member->IsFunction()) {
    strcpy(message, MSG_NO_CLEAR_DEFINED);
    v8res->context->Exit();
    return INIT_ERROR;
  }
  func = v8::Handle<v8::Function>::Cast(member);
  v8res->clear = v8::Persistent<v8::Function>::New(func);
  v8res->compiled |= COMPILED_CLEAR;

  member = global->Get(str_agg);
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
  v8::Handle<v8::Value> member = global->Get(str_deinit);
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

  str_init = v8::Persistent<v8::String>::New(v8::String::New("init"));
  str_udf = v8::Persistent<v8::String>::New(v8::String::New("udf"));
  str_agg = v8::Persistent<v8::String>::New(v8::String::New("agg"));
  str_clear = v8::Persistent<v8::String>::New(v8::String::New("clear"));
  str_deinit = v8::Persistent<v8::String>::New(v8::String::New("deinit"));

  str_STRING_RESULT = v8::Persistent<v8::String>::New(v8::String::New("STRING_RESULT"));
  str_INT_RESULT = v8::Persistent<v8::String>::New(v8::String::New("INT_RESULT"));
  str_DECIMAL_RESULT = v8::Persistent<v8::String>::New(v8::String::New("DECIMAL_RESULT"));
  str_REAL_RESULT = v8::Persistent<v8::String>::New(v8::String::New("REAL_RESULT"));
  str_ROW_RESULT = v8::Persistent<v8::String>::New(v8::String::New("ROW_RESULT"));
  str_DECIMAL_RESULT = v8::Persistent<v8::String>::New(v8::String::New("DECIMAL_RESULT"));
  str_NOT_FIXED_DEC = v8::Persistent<v8::String>::New(v8::String::New("NOT_FIXED_DEC"));

  int_STRING_RESULT = v8::Persistent<v8::Integer>::New(v8::Uint32::New(STRING_RESULT));
  int_INT_RESULT = v8::Persistent<v8::Integer>::New(v8::Uint32::New(INT_RESULT));
  int_DECIMAL_RESULT = v8::Persistent<v8::Integer>::New(v8::Uint32::New(DECIMAL_RESULT));
  int_REAL_RESULT = v8::Persistent<v8::Integer>::New(v8::Uint32::New(REAL_RESULT));
  int_ROW_RESULT = v8::Persistent<v8::Integer>::New(v8::Uint32::New(ROW_RESULT));
  int_DECIMAL_RESULT = v8::Persistent<v8::Integer>::New(v8::Uint32::New(DECIMAL_RESULT));
  int_NOT_FIXED_DEC = v8::Persistent<v8::Integer>::New(v8::Uint32::New(NOT_FIXED_DEC));

  str_mysql = v8::Persistent<v8::String>::New(v8::String::New("mysql"));
  str_console = v8::Persistent<v8::String>::New(v8::String::New("console"));
  str_require = v8::Persistent<v8::String>::New(v8::String::New("require"));

  str_arguments = v8::Persistent<v8::String>::New(v8::String::New("arguments"));
  str_const_item = v8::Persistent<v8::String>::New(v8::String::New("const_item"));
  str_decimals = v8::Persistent<v8::String>::New(v8::String::New("decimals"));
  str_maybe_null = v8::Persistent<v8::String>::New(v8::String::New("maybe_null"));
  str_max_length = v8::Persistent<v8::String>::New(v8::String::New("max_length"));
  str_name = v8::Persistent<v8::String>::New(v8::String::New("name"));
  str_type = v8::Persistent<v8::String>::New(v8::String::New("type"));
  str_value = v8::Persistent<v8::String>::New(v8::String::New("value"));

  str_resultset = v8::Persistent<v8::String>::New(v8::String::New("resultset"));
  str_resultinfo = v8::Persistent<v8::String>::New(v8::String::New("resultinfo"));

  str_charsetnr = v8::Persistent<v8::String>::New(v8::String::New("charsetnr"));
  str_org_name = v8::Persistent<v8::String>::New(v8::String::New("org_name"));
  str_table = v8::Persistent<v8::String>::New(v8::String::New("table"));
  str_org_table = v8::Persistent<v8::String>::New(v8::String::New("org_table"));
  str_length = v8::Persistent<v8::String>::New(v8::String::New("length"));
  str_primary_key = v8::Persistent<v8::String>::New(v8::String::New("in_primary_key"));
  str_unique_key = v8::Persistent<v8::String>::New(v8::String::New("in_unique_key"));
  str_multiple_key = v8::Persistent<v8::String>::New(v8::String::New("in_multiple_keys"));
  str_unsigned = v8::Persistent<v8::String>::New(v8::String::New("is_unsigned"));
  str_zerofill = v8::Persistent<v8::String>::New(v8::String::New("is_zerofill"));
  str_binary = v8::Persistent<v8::String>::New(v8::String::New("is_binary"));
  str_auto_increment = v8::Persistent<v8::String>::New(v8::String::New("is_auto_increment"));
  str_enum = v8::Persistent<v8::String>::New(v8::String::New("is_enum"));
  str_set = v8::Persistent<v8::String>::New(v8::String::New("is_set"));
  str_numeric = v8::Persistent<v8::String>::New(v8::String::New("is_numeric"));

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

  str_sql = v8::Persistent<v8::String>::New(v8::String::New("sql"));
  str_done = v8::Persistent<v8::String>::New(v8::String::New("done"));
  str_rowcount = v8::Persistent<v8::String>::New(v8::String::New("rowCount"));
  str_info = v8::Persistent<v8::String>::New(v8::String::New("info"));

  str_err_setting_api_constant = v8::Persistent<v8::String>::New(v8::String::New(MSG_ERR_SETTING_API_CONSTANT));
  str_unsupported_type = v8::Persistent<v8::String>::New(v8::String::New(MSG_UNSUPPORTED_TYPE));
  str_string_conversion_failed = v8::Persistent<v8::String>::New(v8::String::New(MSG_STRING_CONVERSION_FAILED));

  str_connection_already_closed = v8::Persistent<v8::String>::New(v8::String::New(MSG_CONNECTION_ALREADY_CLOSED));
  str_not_all_results_consumed = v8::Persistent<v8::String>::New(v8::String::New(MSG_NOT_ALL_RESULTS_CONSUMED));
  str_resultset_already_exhausted = v8::Persistent<v8::String>::New(v8::String::New(MSG_RESULTSET_ALREADY_EXHAUSTED));
  str_field_index_must_be_int = v8::Persistent<v8::String>::New(v8::String::New(MSG_FIELD_INDEX_MUST_BE_INT));
  str_field_index_out_of_range = v8::Persistent<v8::String>::New(v8::String::New(MSG_FIELD_INDEX_OUT_OF_RANGE));
  str_expected_zero_arguments = v8::Persistent<v8::String>::New(v8::String::New(MSG_EXPECTED_ZERO_ARGUMENTS));
  str_expected_one_argument = v8::Persistent<v8::String>::New(v8::String::New(MSG_EXPECTED_ONE_ARGUMENT));
  str_arg_must_be_array_or_object_or_function = v8::Persistent<v8::String>::New(v8::String::New(MSG_ARG_MUST_BE_ARRAY_OR_OBJECT_OR_FUNCTION));
  str_arg_must_be_string = v8::Persistent<v8::String>::New(v8::String::New(MSG_ARG_MUST_BE_STRING));
  str_arg_must_be_object = v8::Persistent<v8::String>::New(v8::String::New(MSG_ARG_MUST_BE_OBJECT));
  str_arg_must_be_array = v8::Persistent<v8::String>::New(v8::String::New(MSG_ARG_MUST_BE_ARRAY));
  str_arg_must_be_boolean = v8::Persistent<v8::String>::New(v8::String::New(MSG_ARG_MUST_BE_BOOLEAN));
  str_first_arg_must_be_function = v8::Persistent<v8::String>::New(v8::String::New(MSG_FIRST_ARG_MUST_BE_FUNCTION));
  str_second_arg_must_be_object = v8::Persistent<v8::String>::New(v8::String::New(MSG_SECOND_ARG_MUST_BE_OBJECT));
  str_host_must_be_string = v8::Persistent<v8::String>::New(v8::String::New(MSG_HOST_MUST_BE_STRING));
  str_user_must_be_string = v8::Persistent<v8::String>::New(v8::String::New(MSG_USER_MUST_BE_STRING));
  str_password_must_be_string = v8::Persistent<v8::String>::New(v8::String::New(MSG_PASSWORD_MUST_BE_STRING));
  str_schema_must_be_string = v8::Persistent<v8::String>::New(v8::String::New(MSG_SCHEMA_MUST_BE_STRING));
  str_socket_must_be_string = v8::Persistent<v8::String>::New(v8::String::New(MSG_SOCKET_MUST_BE_STRING));
  str_port_must_be_int = v8::Persistent<v8::String>::New(v8::String::New(MSG_PORT_MUST_BE_INT));
  str_err_connecting_to_mysql = v8::Persistent<v8::String>::New(v8::String::New(MSG_ERR_CONNECTING_TO_MYSQL));
  str_could_not_allocate_mysql_resource = v8::Persistent<v8::String>::New(v8::String::New(MSG_COULD_NOT_ALLOCATE_MYSQL_RESOURCE));
  str_member_sql_must_be_string = v8::Persistent<v8::String>::New(v8::String::New(MSG_MEMBER_SQL_MUST_BE_STRING));
  str_query_already_prepared = v8::Persistent<v8::String>::New(v8::String::New(MSG_QUERY_ALREADY_PREPARED));
  str_failed_to_allocate_statement = v8::Persistent<v8::String>::New(v8::String::New(MSG_FAILED_TO_ALLOCATE_STATEMENT));
  str_failed_to_allocate_field_extractors = v8::Persistent<v8::String>::New(v8::String::New(MSG_FAILED_TO_ALLOCATE_FIELD_EXTRACTORS));
  str_resultset_already_consumed = v8::Persistent<v8::String>::New(v8::String::New(MSG_RESULTSET_ALREADY_EXHAUSTED));
  str_query_not_yet_done = v8::Persistent<v8::String>::New(v8::String::New(MSG_QUERY_NOT_YET_DONE));
  str_results_already_consumed = v8::Persistent<v8::String>::New(v8::String::New(MSG_RESULTS_ALREADY_CONSUMED));

  mysqlExceptionTemplate = createMysqlExceptionTemplate();
  mysqlQueryResultSetTemplate = createMysqlQueryResultSetTemplate();
  mysqlQueryResultInfoTemplate = createMysqlQueryResultInfoTemplate();
  mysqlQueryTemplate = createMysqlQueryTemplate();
  mysqlConnectionTemplate = createMysqlConnectionTemplate();
  mysqlClientTemplate = createMysqlClientTemplate();
  mysqlTemplate = createMysqlTemplate();

  consoleTemplate = createConsoleTemplate();
  globalTemplate = createGlobalTemplate();
  globalTemplateForUDFs = createGlobalTemplateForUDFs();

  jsDaemonContext->Exit();

  LOG_ERR(MSG_JS_DAEMON_STARTED);
  return 0;
}

static int js_daemon_plugin_deinit(MYSQL_PLUGIN){
  LOG_ERR(MSG_JS_DAEMON_SHUTTING_DOWN);
  v8::Locker locker;
  v8::HandleScope handle_scope;
  jsDaemonContext->Enter();

  globalTemplateForUDFs.Dispose();
  globalTemplate.Dispose();
  consoleTemplate.Dispose();

  mysqlTemplate.Dispose();
  mysqlClientTemplate.Dispose();
  mysqlConnectionTemplate.Dispose();
  mysqlQueryTemplate.Dispose();
  mysqlQueryResultSetTemplate.Dispose();
  mysqlQueryResultInfoTemplate.Dispose();
  mysqlExceptionTemplate.Dispose();

  str_init.Dispose();
  str_udf.Dispose();
  str_agg.Dispose();
  str_clear.Dispose();
  str_deinit.Dispose();

  str_console.Dispose();
  str_mysql.Dispose();
  str_require.Dispose();

  str_STRING_RESULT.Dispose();
  str_INT_RESULT.Dispose();
  str_DECIMAL_RESULT.Dispose();
  str_REAL_RESULT.Dispose();
  str_ROW_RESULT.Dispose();
  str_DECIMAL_RESULT.Dispose();
  str_NOT_FIXED_DEC.Dispose();

  str_resultset.Dispose();
  str_resultinfo.Dispose();

  int_STRING_RESULT.Dispose();
  int_INT_RESULT.Dispose();
  int_DECIMAL_RESULT.Dispose();
  int_REAL_RESULT.Dispose();
  int_ROW_RESULT.Dispose();
  int_DECIMAL_RESULT.Dispose();
  int_NOT_FIXED_DEC.Dispose();

  str_arguments.Dispose();
  str_const_item.Dispose();
  str_decimals.Dispose();
  str_maybe_null.Dispose();
  str_max_length.Dispose();
  str_name.Dispose();
  str_type.Dispose();
  str_value.Dispose();

  str_charsetnr.Dispose();
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
  str_enum.Dispose();
  str_set.Dispose();
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

  str_sql.Dispose();
  str_done.Dispose();
  str_rowcount.Dispose();
  str_info.Dispose();

  str_err_setting_api_constant.Dispose();
  str_unsupported_type.Dispose();
  str_string_conversion_failed.Dispose();

  str_connection_already_closed.Dispose();
  str_not_all_results_consumed.Dispose();
  str_resultset_already_exhausted.Dispose();
  str_field_index_must_be_int.Dispose();
  str_field_index_out_of_range.Dispose();
  str_expected_zero_arguments.Dispose();
  str_expected_one_argument.Dispose();
  str_arg_must_be_array_or_object_or_function.Dispose();
  str_arg_must_be_string.Dispose();
  str_arg_must_be_object.Dispose();
  str_arg_must_be_array.Dispose();
  str_arg_must_be_boolean.Dispose();
  str_first_arg_must_be_function.Dispose();
  str_second_arg_must_be_object.Dispose();
  str_host_must_be_string.Dispose();
  str_user_must_be_string.Dispose();
  str_password_must_be_string.Dispose();
  str_schema_must_be_string.Dispose();
  str_socket_must_be_string.Dispose();
  str_port_must_be_int.Dispose();
  str_err_connecting_to_mysql.Dispose();
  str_could_not_allocate_mysql_resource.Dispose();
  str_member_sql_must_be_string.Dispose();
  str_query_already_prepared.Dispose();
  str_failed_to_allocate_statement.Dispose();
  str_failed_to_allocate_field_extractors.Dispose();
  str_resultset_already_consumed.Dispose();
  str_query_not_yet_done.Dispose();
  str_results_already_consumed.Dispose();

  clear_module_cache();

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
  PLUGIN_NAME,
  "Roland Bouman",
  "Javascript Daemon - Manages resources for the js* UDFs - https://github.com/rpbouman/mysqlv8udfs",
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
