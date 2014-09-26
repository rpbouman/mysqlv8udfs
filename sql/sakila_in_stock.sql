select inventory_id
from sakila.inventory
where jsudf('
  var conn, query1, query2;
  function init(){
    var args = this.arguments;
    if (args.length !== 1 || args[0].type !== INT_RESULT) {
      throw "Expect exactly 1 integer argument"
    }
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

    var query, result, arr = [];
    query = conn.query(
      "SELECT COUNT(*) " +
      "FROM rental " +
      "WHERE inventory_id = " + inventory_id
    );
    query.execute();
    result = query.result();
    result.fetchArray(arr);
    if (arr[0] === "0") return true;

    query = conn.query(
      "SELECT COUNT(*) " +
      "FROM inventory " +
      "LEFT JOIN rental " +
      "USING(inventory_id) " +
      "WHERE rental.return_date IS NULL " +
      "AND inventory_id = " + inventory_id
    );
    query.execute();
    result = query.result();
    result.fetchArray(arr);
    if (arr[0] === "0") return true;

    return false;
  }
', inventory_id) = 'false';


select inventory_id
from sakila.inventory
where jsudf('
  var conn, query1, query2;
  function init(){
    var args = this.arguments;
    if (args.length !== 1 || args[0].type !== INT_RESULT) {
      throw "Expect exactly 1 integer argument"
    }
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

    var query, result, arr = [];
    query = conn.query(
      "SELECT COUNT(*) " +
      "FROM rental " +
      "WHERE inventory_id = " + inventory_id +
      ";" +
      "SELECT COUNT(*) " +
      "FROM inventory " +
      "LEFT JOIN rental " +
      "USING(inventory_id) " +
      "WHERE rental.return_date IS NULL " +
      "AND inventory_id = " + inventory_id
    );
    query.execute();
    result = query.result();
    result.fetchArray(arr);
    if (arr[0] === "0") return true;
    result = query.result();
    result.fetchArray(arr);
    if (arr[0] === "0") return true;

    return false;
  }
', inventory_id) = 'false';


select jsudf('
  var conn, query1, query2;
  function init(){
    console.log("Establishing connection");
    conn = mysql.client.connect({
      host: "localhost",
      port: 3306,
//      socket: "/home/rbouman/mysql/mysqld.sock",
      user: "sakila",
      password: "sakila",
      schema: "sakila"
    });
  }

  function udf(inventory_id){
    try {
      var query, result, rows, ret = [];
      query = conn.query(
        "SELECT film_id " +
        "FROM film " +
        "LIMIT 1"
      );
      query.execute();
      while (!query.done) {
        rows = [];
        ret.push(rows);
        result = query.result();
        console.log("row count: " + result.rowCount);
        while (!result.done) {
          rows.push(result.row());
        };
      }
      return JSON.stringify(rows, null, 2);
    }
    catch (exception) {
      console.log("Whoops, exception");
      return JSON.stringify(exception, null, 2);
    }
  }

  function deinit(){
    console.log("Closing connection");
    conn.close();
  }
');
