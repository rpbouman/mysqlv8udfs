(function(){

  this.init = function(){
    if (this.arguments.length < 2) {
      throw "You must supply at least 2 arguments.";
    }
  };

  function merge(dest, src){
    if (typeof(src) !== "object") {
      return;
    }
    else
    if (dest instanceof Array && src instanceof Array) {
      var i, n = src.length;
      for (i = 0; i < n; i++) {
        dest.push(src[i]);
      }
      return;
    }
    var prop, val;
    for (prop in src) {
      val = src[prop];
      switch (typeof(dest[prop])) {
        case "object":
          merge(dest[prop], val);
          break;
        default:
          dest[prop] = val;
          break;
      }
    }
  }

  this.udf = function(){
    var doc = JSON.parse(arguments[0]);
    var o = doc, i, n = arguments.length;
    for (i = 1; i < n; i++) {
      merge(doc, JSON.parse(arguments[i]));
    }
    return JSON.stringify(doc, null, " ");
  }

})();
