(function(){
  this.init = function(){
    if (this.arguments.length < 1) {
      throw "You must supply at least 1 argument.";
    }
  }

  this.udf = function(){
    var i, n = arguments.length, ret = true;
    try {
      for (i = 0; i < n; i++) {
        JSON.parse(arguments[i]);
      }
    }
    catch (exception) {
      ret = false;
    }
    return ret;
  };

})();
