(function(){

  this.init = function(){
    if (this.arguments.length < 2) {
      throw "You must supply at least 2 arguments.";
    }
  };

  this.udf = function(){
    var doc = JSON.parse(arguments[0]);
    var o = doc, i, n = arguments.length, arg;
    for (i = 1; i < n; i++) {
      arg = arguments[i];
      o = o[arg];
      if (typeof(o) === "undefined") {
        //apparently, this path does not exist
        return false;
      }
    }
    return true;
  }

})();
