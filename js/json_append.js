(function(){
  this.init = function(){
    if (this.arguments.length < 3) {
      throw "You must supply at least 3 arguments.";
    }
  }

  this.udf = function(){
    var doc = JSON.parse(arguments[0]);

    //locate the item in the doc
    var o = doc, oo, i, n = arguments.length - 2, arg;
    for (i = 1; i < n; i++) {
      arg = arguments[i];
      oo = o[arg];
      if (typeof(oo) === "undefined") {
        //apparently, this path does not exist
        return arguments[0];
      }
      o = oo;
    }

    var value = JSON.parse(arguments[n+1]);
    if (o instanceof Array) {
      o.splice(arguments[n], 0, value);
    }
    else {
      o[arguments[n]] = value;
    }
    return JSON.stringify(doc, null, " ");
  };

})();
