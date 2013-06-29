//prepare example
select jsudf('
 var connection;

 function init(){
  connection = mysql.client.connect({user: "sakila", password: "sakila", schema: "sakila"});
 }
 function deinit(){
  connection.close();
 }
 function udf(){
  var query = connection.query("select * from film where film_id = 1");
  query.prepare();
  query.execute();
  var result = query.result();
  var array = result.fetchArray();
  return JSON.stringify(array);
  //query.prepare();
  //return query.paramCount();
 }
') q;

select js('
 var conn = mysql.client.connect({
   user: "sakila",
   password: "sakila"
 });
 var query = conn.query("select version()");
 query.execute();
 var result = query.result();
 var row = result.fetchArray([]);
 JSON.stringify(row, null, " ");
');

select jsudf('
function udf(){
 var conn = mysql.client.connect({
   user: "sakila",
   password: "sakila"
 });
 var query = conn.query("select version()");
 query.execute();
 var result = query.result();
 var row = result.fetchArray([]);
 return JSON.stringify(row, null, " ");
}
');

select js('
try {
  var conn = mysql.client.connect({
    host: "localhost",
    port: 3306,
    user: "sakila",
    password: "sakila",
    schema: "sakila"
  });
  var query = conn.query("SELECT * FROM category");
  query.execute();

  var row, rows = [];
  var result = query.result();
  while ((row = result.fetchArray()) !== null) {
    rows.push(row);
  }
  JSON.stringify(rows, null, 2);
}
catch (e) {
  e
}
');


select jsudf('
  var conn, query1, query2;
  function init(){
    conn = mysql.client.connect({
      host: "localhost",
//      port: 3306,
      socket: "/home/rbouman/mysql/mysqld.sock",
      user: "sakila",
      password: "sakila",
      schema: "sakila"
    });
  }

  function udf(inventory_id){

    var query, result, rows, ret = [];
    query = conn.query(
      "SELECT film_id " +
      "FROM film " +
      "LIMIT 0"
    );
    query.execute();
    while (!query.done) {
      rows = [];
      ret.push(rows);
      result = query.result();
      while (!result.done) {
        rows.push(result.fetchArray([]));
      };
    }

    return JSON.stringify(rows, null, 2);
  }
', 1);
