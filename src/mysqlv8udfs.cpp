#include "stdlib.h"
#include "string.h"
#include "stdarg.h"
#include "mysql.h"
#include "v8.h"

#define TRUE                            1
#define FALSE                           0
#define JS_MAX_RETURN_VALUE_LENGTH      65535

#define MSG_MISSING_SCRIPT              "Missing script argument."
#define MSG_SCRIPT_MUST_BE_STRING       "Script argument must be a string."
#define MSG_RESOURCE_ALLOCATION_FAILED  "Failed to allocate v8 resources."
#define MSG_CREATE_CONTEXT_FAILED       "Failed to create context."
#define MSG_SCRIPT_COMPILATION_FAILED   "Error compiling script."

#define LOG_ERR(a) fprintf(stderr, "\n%s", a);

#define INIT_ERROR                      1
#define INIT_SUCCESS                    0

char* getExceptionString(v8::TryCatch* try_catch) {
  v8::String::AsciiValue exception(try_catch->Exception());
  return *exception;
}

v8::Handle<v8::Value> Log(const v8::Arguments& args) {
  v8::Handle<v8::Value> value = args[0];
  v8::String::AsciiValue ascii(value);
  fprintf(stderr, "\n%s", *ascii);
  return v8::Undefined();
}

v8::Handle<v8::ObjectTemplate> getConsoleTemplate(){
  v8::Handle<v8::ObjectTemplate> console = v8::ObjectTemplate::New();
  console->Set(v8::String::New("log"), v8::FunctionTemplate::New(Log));
  return console;
}

v8::Handle<v8::Value> getBuiltinConsole(
  v8::Local<v8::String> property,
  const v8::AccessorInfo& info
) {
  return getConsoleTemplate()->NewInstance();
}

v8::Handle<v8::ObjectTemplate> getGlobalTemplate(){
  v8::Handle<v8::ObjectTemplate> global = v8::ObjectTemplate::New();
  global->SetAccessor(v8::String::New("console"), getBuiltinConsole);
  return global;
}

//ARG_EXTRACTOR = pointer to an extractor function
typedef v8::Handle<v8::Value> (*ARG_EXTRACTOR)(UDF_ARGS*, unsigned int);
typedef v8::Handle<v8::Value> (**ARRAY_OF_ARG_EXTRACTORS)(UDF_ARGS*, unsigned int);

typedef struct st_v8_resources {
  v8::Persistent<v8::Context> context;
  v8::Persistent<v8::Script> script;
  v8::Persistent<v8::Array> arguments;
  ARG_EXTRACTOR *arg_extractors;
  my_bool compiled;
  char *result;
  unsigned long long max_result_length;
} V8RES;

v8::Handle<v8::String> getStringArgString(
  UDF_ARGS *args,
  unsigned int i
){
  return v8::String::New(
    args->args[i],
    args->lengths[i]
  );
}

v8::Handle<v8::Value> getStringArgValue(
  UDF_ARGS *args,
  unsigned int i
){
  return v8::String::New(
    args->args[i],
    args->lengths[i]
  );
}

v8::Handle<v8::Value> getIntArgValue(
  UDF_ARGS *args,
  unsigned int i
){
  long long int_val = *((long long *)args->args[i]);
  if (int_val >> 31) return v8::Number::New((double)int_val);
  else return v8::Integer::New(int_val);
}

v8::Handle<v8::Value> getRealArgValue(
  UDF_ARGS *args,
  unsigned int i
){
  return v8::Number::New(*((double *)args->args[i]));
}

void setupArguments(V8RES *v8res, UDF_ARGS* args) {
  //set up arguments.
  //Any arguments beyond the initial "script" argument
  //are available in a global array called arguments
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

void assignArguments(V8RES *v8res, UDF_ARGS* args) {
  ARG_EXTRACTOR arg_extractor;
  v8::Handle<v8::Value> val;
  for (unsigned int i = 1; i < args->arg_count; i++) {
    arg_extractor = v8res->arg_extractors[i];
    //if this is a constant argument, the value is already set
    //so we can skip it.
    if (arg_extractor == NULL) continue;
    //extract and store the argument value
    if (args->args[i] == NULL) val = v8::Null();
    else val = (*arg_extractor)(args, i);
    v8res->arguments->Set(i - 1, val);
  }
}

#ifdef __cplusplus
extern "C" {
#endif

my_bool js_init(
  UDF_INIT *initid,
  UDF_ARGS *args,
  char *message
){
  if (args->arg_count < 1) {
    strcpy(message, MSG_MISSING_SCRIPT);
    return INIT_ERROR;
  }
  if (args->arg_type[0] != STRING_RESULT) {
    strcpy(message, MSG_SCRIPT_MUST_BE_STRING);
    return INIT_ERROR;
  }
  initid->ptr = (char *)malloc(sizeof(V8RES));
  if (initid->ptr == NULL) {
    strcpy(message, MSG_RESOURCE_ALLOCATION_FAILED);
    return INIT_ERROR;
  }
  V8RES *v8res = (V8RES *)initid->ptr;
  v8res->result = NULL;
  v8res->max_result_length = 0;
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

  setupArguments(v8res, args);

  //check if we can pre-compile the script
  if (args->args[0] == FALSE) { //script argument is not a constant.
    v8res->compiled = FALSE;
  }
  else {                    //script argument is a constant, compile it.
    v8res->script = v8::Persistent<v8::Script>::New(
      v8::Script::New(getStringArgString(args, 0))
    );
    if (v8res->script.IsEmpty()) {
      char *exceptionMessage = getExceptionString(&try_catch);
      strcpy(message, exceptionMessage);
      LOG_ERR(MSG_SCRIPT_COMPILATION_FAILED);
      LOG_ERR(exceptionMessage);
      return INIT_ERROR;
    }
    v8res->compiled = TRUE;
  }

  initid->max_length = JS_MAX_RETURN_VALUE_LENGTH;
  v8res->context->Exit();
  return INIT_SUCCESS;
}

void js_deinit(
  UDF_INIT *initid
){
  if (initid->ptr == NULL) return;
  //clean up v8
  V8RES *v8res = (V8RES *)initid->ptr;
  if (v8res->compiled == TRUE) {
    v8res->script.Dispose();
  }
  v8res->arguments.Dispose();
  v8res->context.Dispose();
  v8res->context.Clear();
  if (v8res->result != NULL) free(v8res->result);
  free(v8res->arg_extractors);
  free(v8res);
}

char *js(
  UDF_INIT *initid,
  UDF_ARGS *args,
  char *result,
  unsigned long *length,
  my_bool *is_null,
  my_bool *error
){
  v8::Locker locker;
  v8::TryCatch try_catch;
  V8RES *v8res = (V8RES *)initid->ptr;
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
    script = v8::Script::Compile(getStringArgString(args, 0));
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
    LOG_ERR(getExceptionString(&try_catch));
    *error = TRUE;
    v8res->context->Exit();
    return NULL;
  }

  //return the value returned by the script
  v8::String::AsciiValue ascii(value);
  *length = (unsigned long)ascii.length();
  if (*length > v8res->max_result_length) {
    if (v8res->result != NULL) free(v8res->result);
    v8res->result = (char *)malloc(*length);
    if (v8res->result == NULL) {
      v8res->max_result_length = 0;
      LOG_ERR(MSG_RESOURCE_ALLOCATION_FAILED);
      *error = TRUE;
      v8res->context->Exit();
      return NULL;
    }
    else v8res->max_result_length = *length;
  }
  strcpy(v8res->result, *ascii);
  v8res->context->Exit();
  return v8res->result;
}

#ifdef __cplusplus
};
#endif
