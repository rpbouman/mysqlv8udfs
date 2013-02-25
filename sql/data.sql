INSERT INTO js(name, type, js, description) VALUES
 ('easter', 'js', '
var y = parseInt(arguments[0].substr(0,4), 10),
  a = y % 19,
  b = Math.floor(y / 100),
  c = y % 100,
  d = Math.floor(b / 4),
  e = b % 4,
  f = Math.floor((b + 8) / 25),
  g = Math.floor((b - f + 1) / 3),
  h = (19 * a + b - d - g + 15) % 30,
  i = Math.floor(c / 4),
  k = c % 4,
  L = (32 + 2 * e + 2 * i - h - k) % 7,
  m = Math.floor((a + 11 * h + 22 * L) / 451),
  n = h + L - 7 * m + 114
  ;
  y + "-" + (Math.floor(n/31)) + "-" + ((n%31)+1);
', '')
,('count', 'jsagg', '
  var count;
  function clear(){
    count = 0;
  }
  function udf(){
    count++;
  }
  function agg(){
    return count;
  }
', 'JS equivalent of COUNT')
,('count_distinct', 'jsagg', '
  var count, map, args = arguments, n = args.length, i;
  function clear(){
    count = 0;
    map = {};
  }
  function udf(){
    var v, e, u, m = map;
    console.log("count-distinct");
    for (i = 0; i < n; i++) {
      v = args[i].value;
      console.log("arg" + i + ": " + v);
      e = m[v];
      if (typeof(e) === "undefined") {
        u = true;
        m[v] = e = {};
      }
      m = e;
    }
    if (u) count++;
  }
  function agg(){
    return count;
  }
', 'JS equivalent of COUNT')
,('json_export', 'jsagg', '
  var rows;
  function clear() {
    rows = [];
  }
  function udf(){
    var i, arg, args = this.arguments, n = args.length, row = {};
    for (i = 0; i < n;  i++) {
      arg = args[i];
      row[arg.name] = arg.value;
    }
    rows.push(row);
  }
  function agg(){
    return JSON.stringify(rows);
  }
', 'Export data as JSON')
