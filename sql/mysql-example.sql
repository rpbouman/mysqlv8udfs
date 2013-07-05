-- prepare example
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
  var array = result.row();
  return JSON.stringify(array);
  //query.prepare();
  //return query.paramCount();
 }
') q;

-- minimal example
select js('
 var conn = mysql.client.connect({
   user: "sakila",
   password: "sakila"
 });
 var query = conn.query("select version();;");
 query.execute();
 var result = query.result();
 var row = result.row([]);
 JSON.stringify(row, null, " ");
');

-- ddl/dml example
select js('
 var conn = mysql.client.connect({
   user: "root",
   password: "mysql",
   schema: "test"
 });
 conn.query("drop table if exists t").execute();
 conn.query("create table t(id int)").execute();
 var query = conn.query("insert into t values (1)");
 query.execute();
 JSON.stringify(query.result());
');


-- metadata example
select js('
 var str = "";
 var conn = mysql.client.connect({
   user: "root",
   password: "mysql",
   schema: "test"
 });
 var query = conn.query("select * from test.charset");
 query.execute();
 var result = query.result();

 str += "fieldcount: " + result.fieldCount;
 var field, fields = [];
 while (field = result.field()) {
  field.type = mysql.types[field.type];
  fields.push(field);
 }
 str += "fields: " + JSON.stringify(fields, null, " ");
 str;
');

-- getting an invalid field
select js('
 var conn = mysql.client.connect({
   user: "sakila",
   password: "sakila"
 });
 var query = conn.query("select * from sakila.film limit 0");
 query.execute();
 var result = query.result();
 var field, fields = [];
 try {
  field = result.field(100)
 }
 catch (e){
  JSON.stringify(e, null, " ");
 }
');

-- call example
select js('
 try {
   var str = "";
   var conn = mysql.client.connect({
     user: "sakila",
     password: "sakila",
     schema: "sakila"
   });
   var query, result, resultCount = 0, row, rowCount;

   try {
     query = conn.query("create procedure p() select 1;");
     query.execute();
   }
   catch (e) {
     if(e.code === 1304) str += "\\nProcedure p already exists.";
     else throw e;
   }
   query = conn.query("call p();");
   query.execute();
   while (result = query.result()) {
    resultCount++;
    str += "\\nResult " + resultCount;
    rowCount = 0;
    while (row = result.row([])) {
     rowCount++;
     str += "\\nrow " + rowCount + ": " + JSON.stringify(row, null, "");
    }
    break;
   }
   str;
 } catch(e){
   JSON.stringify(e, null, "");
 }
') q;


-- multiple statement example
select js('
 var str = "";
 var conn = mysql.client.connect({
   user: "sakila",
   password: "sakila"
 });
 var result, resultCount = 0, row, rowCount;
 var query = conn.query("select version(); select version()");
 query.execute();
 while (result = query.result()) {
  resultCount++;
  str += "\\nResult " + resultCount;
  rowCount = 0;
  while (row = result.row([])) {
   rowCount++;
   str += "\\nrow " + rowCount + ": " + JSON.stringify(row, null, "");
  }
  break;
 }
 str;
') q;


-- handling query error
select js('
 var conn = mysql.client.connect({
   user: "sakila",
   password: "sakila"
 });
 var query = conn.query("select version()");
 try {
  query.execute();
 true;
 } catch (e) {
  JSON.stringify(e, null, " ");
 }
 try {
  var result = query.result();
  result.done;
 }
 catch (e) {
  JSON.stringify(e, null, " ");
 }
');

//getting a row
select jsudf('
function udf(){
 var conn = mysql.client.connect({
   user: "sakila",
   password: "sakila"
 });
 var query = conn.query("select version()");
 query.execute();
 var result = query.result();
 var row = result.row([]);
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
  var query = conn.query("SELECT * FROM film LIMIT 3");
  query.execute();

  var row, rows = [];
  var result = query.result();
  while ((row = result.row({})) !== null) {
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
        rows.push(result.row([]));
      };
    }

    return JSON.stringify(rows, null, 2);
  }
', 1);
