(function(){

  this.init = function(){
    if (this.arguments.length < 2) {
      throw "You must supply at least 2 arguments.";
    }
  };

  this.udf = function(){
    var doc = JSON.parse(arguments[0]);
    var o = doc, i, n = arguments.length - 1, arg;
    for (i = 1; i < n; i++) {
      arg = arguments[i];
      o = o[arg];
      if (typeof(o) === "undefined") {
        //apparently, this path does not exist
        return arguments[0];
      }
    }
    if (o instanceof Array){
      o.splice(arguments[n], 1);
    }
    else {
      delete o[arguments[n]];
    }
    return JSON.stringify(doc, null, " ");
  }

})();
