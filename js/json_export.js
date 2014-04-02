/**
 *  json_export - generate a json document
 *
 *  usage:
 *
 *  select jsagg('require("json_export.js");', film_id, title, release_year) from sakila.film;
 *
 *  result:
 *
 *  {
 *  }
 * 
 */
(function json_export(){
  var rows, row, i, arg, args = this.arguments, n = args.length;

  this.clear = function(){
    rows = [];
  }

  this.udf = function() {
    var row = {};
    for (i = 0; i < n; i++) {
      arg = args[i];
      row[arg.name] = arg.value;
    }
    
    if (rows) {
      rows.push(row);
    }
    else {
      return JSON.stringify(row, null, " ");
    }
  }

  this.agg = function(){
    return JSON.stringify(rows, null, " ");
  }
})();
