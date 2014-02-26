mysqlv8udfs
===========

MySQL UDFs to work with the Google v8 javascript engine

This project provides the code for a MySQL server plugin and a number of MySQL User-defined functions (UDFs) that expose Google's v8 javascript engine in MySQL queries and stored routines.
Here's a summary of what it provides:
* UDF js(script[, arg1, ..., argN]) - execute a snippet of js and return the value.
* UDF jsudf(script[, arg1, ..., argN]) - exposes MySQL's native UDF interface to the javascript environment.
* UDF jsagg(script[, arg1, ..., argN]) - exposes MySQL's native UDF interface for aggregate functions to the javascript environment. 

In addition, a built-in mysql client API is provided that let's you run MySQL commands and consume results - in Javascript! 

How to build
------------
This is the line that works for me:

    g++ -Wall -I include -I /home/rbouman/mysql/mysql/include -shared -fPIC -DMYSQL_DYNAMIC_PLUGIN -o mysqlv8udfs.so mysqlv8udfs.cpp /usr/lib/libv8.so ~/mysql/mysql/lib/libmysqlclient.so

(This works on KUbuntu 12.10 LTS, and on Ubuntu 13 Saucy. In my case, mysql is installed (from tar.gz archive) in ~/mysql/mysql. I tried with both MySQL 5.6 and MySQL 5.7. I also installed the g++ and libv8-dev packages using Ubuntu Software Center. v8 version: libv8-3.14, g++ 4.8.1-2)

Here are the exact steps that MAC Users can use for building dylib from your code:

Dependencies:
1. Brew
    Installation: ruby -e "$(curl -fsSL https://raw.github.com/Homebrew/homebrew/go/install)”
2. MySQL 
    Installation : brew install mysql
    Tested Version:  5.6.14, could work with any mysql 5.6 versions
3. V8 Engine -  3.15.11
    Installation steps:
    1. brew versions v8 - This will list out all versions of v8 that brew has
    We are interested in version 3.15.11
    2. cd `brew —prefix`
    3. git checkout cb30f36 Library/Formula/v8.rb
    4. brew install v8
    5. g++ -Wall -I include -I  /usr/local/Cellar/mysql/5.6.14/include/mysql -dynamiclib -o mysqlv8udfs.dylib -DMYSQL_DYNAMIC_PLUGIN mysqlv8udfs.cpp /usr/local/Cellar/v8/3.15.11/lib/libv8.dylib /usr/local/Cellar/mysql/5.6.14/lib/libmysqlclient.dylib 

(you should modify the paths to match the location of MySQL and libv8 on your system, and the install.sql has to be changed to read from .dylib instead of .so's)

WARNING: It seems OSX comes with a newer version of v8, like 3.21.17 or higher. Unfortunately, this currently won't compile. 

Hopefully I can manage to wrap my head around libtool and autoconf and whatnot so I can come up with a build process that works for everybody. If anybody would like to contribute that, then please go ahead, I'd welcome it with open arms :).

How to install
--------------
Once you managed to pass the build, you should have a `mysqlv8udfs.so` file. First, you should place this file in MySQL's `plugin` dir. You can find out where that is by running this query:

    SHOW VARIABLES LIKE 'plugin_dir'

After moving the `mysqlv8udfs.so` to the `plugin` dir, you can install the udfs into MySQL by running the `install.sql` script. You should run the script under MySQL's `root` account.

If you ran the `install.sql` script successfully you should now have 3 new UDFs. You can check it by running this query:

    mysql> SELECT * FROM mysql.func WHERE name LIKE 'js%';
    +-------+-----+----------------+-----------+
    | name  | ret | dl             | type      |
    +-------+-----+----------------+-----------+
    | js    |   0 | mysqlv8udfs.so | function  |
    | jsagg |   0 | mysqlv8udfs.so | aggregate |
    | jsudf |   0 | mysqlv8udfs.so | function  |
    +-------+-----+----------------+-----------+
    3 rows in set (0.00 sec)

You should see 3 rows.

Using the js UDF
----------------
The `js` UDF is the simplest but also least powerful. It requires at least 1 argument, which must of the string type and contain a valid javascript snippet.

The UDF will compile the javascript code (if possible, only once) and then run it for each row, returning the value of the last expression in the script (as a string):

    mysql> SELECT js('1 + 1');
    +-------------+
    | js('1 + 1') |
    +-------------+
    | 2           |
    +-------------+
    1 row in set (0.00 sec)

You can pass more than one argument to the `js` function. The values of these extra arguments are exposed to the javascript runtime via the built-in `arguments` array:

    mysql> SELECT js('arguments[0] + arguments[1]', 1, 1);
    +-----------------------------------------+
    | js('arguments[0] + arguments[1]', 1, 1) |
    +-----------------------------------------+
    | 2                                       |
    +-----------------------------------------+
    1 row in set (0.01 sec)

Using the jsudf UDF
-------------------
The `jsudf` UDF exposes MySQL's native User-defined function interface to the javascript runtime. (See http://dev.mysql.com/doc/refman/5.6/en/adding-udf.html for more information)

Just like the `js` function, it expects the first argument to be a string containing a snippet of javascript. Unlike the `js` function, `jsudf` expects the script argument to be static (=the same for all rows). It compiles the script once, and runs it immediately.

After running the script, `jsudf` then looks for a javascript function called `udf`. This `udf` function is then called for each row, and its return value is returned to the MySQL query.

    mysql> select jsudf('
       -'> function udf(){
       -'>   return 1+1;
       -'> ') jsudf;
    +-------+
    | jsudf |
    +-------+
    | 2     |
    +-------+
    1 row in set (0.00 sec)

Any extra arguments passed to the `jsudf` function are available in the script. However, instead of only exposing the argument values like the `js` function does, `jsudf` exposes argument objects:

    mysql> select jsudf('
       -'> function udf(){
       -'>   return JSON.stringify(this.arguments, null, 2);
       -'> }', 'string', 6.626068e-34, 299792458, 3.1415) jsudf;

(The snippet above uses the javascript built-in JSON object to serialize the arguments array to a JSON string, which is returned. Note that inside the udf function, the arguments arrays is referred to using this.arguments rather than arguments.)

The result is something like this:

    [
      {
        "name": "'string'",
        "type": 0,
        "max_length": 6,
        "value": "string",
        "maybe_null": false
      },
      {
        "name": "6.626068e-34",
        "type": 1,
        "max_length": 12,
        "value": 6.626068e-34,
        "maybe_null": false
      },
      {
        "name": "299792458",
        "type": 2,
        "max_length": 9,
        "value": 299792458,
        "maybe_null": false
      },
      {
        "name": "3.1415",
        "type": 4,
        "max_length": 6,
        "value": "3.1415",
        "maybe_null": false
      }
    ]

Each entry in the returned array represents an argument passed to the `jsudf` function. The fields for these argument objects correspond directly to the `UDF_ARGS` structure of the MySQL native UDF interface. (See http://dev.mysql.com/doc/refman/5.6/en/udf-arguments.html for more information)

The MySQL UDF interface also supports an `init` and a `deinit` function. So does the `jsudf`: if the initial script contains a `init` javascript function, then this will be called prior to any calls to the `udf` function. Likewise, if there is a `deinit` function, then it will be called after all calls to the `udf` function have been made.

Using the jsagg UDF
-------------------
The `jsagg` function lets you write a MySQL aggregate function in javascript. It's in many ways like the `jsudf` function: it accepts an initial static string argument which must contain valid javascript. It runs it immediately and then looks for the following javascript functions:

* `init`: this will be called prior to any processing.
* `clear`: this is called right before processing a group of rows.
* `udf`: this is called for each row in the group.
* `agg`: this is called right after processing a group of rows. This function should return the aggregated value which is returned to MySQL
* `deinit`: this is called after all processing is done.

Here's a simple example that implements COUNT(*) as a javascript function:

    mysql> select jsagg('
       -'>   var count;
       -'>   function clear(){
       -'>     count = 0;
       -'>   }
       -'>   function udf(){
       -'>     count++;
       -'>   }
       -'>   function agg(){
       -'>     return count;
       -'>   }
       -'> ') from sakila.category;


