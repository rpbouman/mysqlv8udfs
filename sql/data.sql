INSERT INTO js(name, type, code, description) VALUES
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
,('regexp', 'jsudf', '
  var argv = this.arguments;
  var argc = argv.length;
  var regexp;

  function init() {
    var arg;
    //check number of arguments
    if (argc < 2 || argv > 4) {
      throw "Invalid number of arguments.";
    }

    //check argument 1, (the regular expression)
    arg = argv[0];
    if (arg.type !== STRING_RESULT) {
      throw "Argument 1 must be a string.";
    }
    //if constant, compile a regex once upfront.
    if (arg.const_item) {
      regexp = new RegExp(arg.value);
    }

    //check argument 2, (the string to match)
    arg = argv[1];
    if (arg.type !== STRING_RESULT) {
      throw "Argument 2 must be a string.";
    }

    if (argc == 2) {
      //we will 1 or 0 for match or no match,
      //this is only 1 char wide:
      this.max_length = 1;
      return;
    }

    //check (optional) argument 3, the group to capture
    arg = argv[2];
    switch (arg.type) {
      case INT_RESULT:
        break;
      case DECIMAL_RESULT:
      case REAL_RESULT:
        //Make mysql coerce this into an integer type.
        arg.type = INT_RESULT;
        break;
      default:
        throw "Argument 3 must be an integer."
    }
  }

  function udf(){
    var re = regexp ? regexp : new RegExp(argv[0].value);
    if (argv == 2)
      return re.test(argv[1].value) ? 1 : 0;
    }
    else {
      return re.exec(argv[1].value)[argv[2].value];
    }
  }
', '')
,('count_all', 'jsagg', '
  var count;
  function init(){
    if (this.arguments.length) throw "This script cannot take any arguments.";
  }
  function clear(){
    count = 0;
  }
  function udf(){
    count++;
  }
  function agg(){
    return count;
  }
', 'JS equivalent of COUNT(*)')
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
', 'JS equivalent of COUNT(DISTINCT )')
,('json_row', 'jsudf', '
  function udf(){
    var i, arg, args = this.arguments, n = args.length, row = {};
    for (i = 0; i < n;  i++) {
      arg = args[i];
      row[arg.name] = arg.value;
    }
    return JSON.stringify(row, null, "");
  }
', 'Export arguments as a JSON object.')
,('json_rows', 'jsagg', '
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
    return JSON.stringify({cols: this.arguments, rows: rows}, null, 2);
  }
', 'Export resultset as a JSON object.')
,('group_concat', 'jsagg', '
  var values;
  function clear(){
    values = [];
  }
  function udf(){
    values.push(this.arguments[0].value)
  }
  function agg(){
    return values.join();
  }
', 'A very simple and limited version of the native GROUP_CONCAT')
,('inventory_in_stock', 'jsudf', '
var connection;

function init(){
  connection = mysql.client.connect({
    socket: "/home/rbouman/mysql/mysqld.sock",
    user: "sakila",
    password: "sakila",
    schema: "sakila"
  });
}

function udf(id){
  try{
    var query, result, fields;
    query = connection.query("select count(*) from rental where inventory_id = " + id);
    query.execute();
    result = query.result();
    fields = result.fetchArray();
    if (fields[0] === 0) return true;

    query = connection.query(
      "select count(rental_id) " +
      "from inventory " +
      "left join rental " +
      "using(inventory_id) " +
      "where inventory.inventory_id = " + id + " " +
      "and rental.return_date is null"
    );
    query.execute();
    result = query.result();
    fields = result.fetchArray();
    return fields[0] > 0 ? false : true
  } catch(e) {
    return JSON.stringify(e);
  }
}

function deinit(){
  connection.close();
}
', 'equivalent to the sakila.inventory_in_stock stored function')
;
