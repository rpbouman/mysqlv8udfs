mysqlv8udfs
===========

MySQL UDFs to work with the Google v8 javascript engine

How to build
------------
This is the line that works for me:

    g++ -Wall -I include -I ~/mysql/mysql/include -shared -fPIC -o mysqlv8udfs.so mysqlv8udfs.cpp /usr/lib/libv8.so

(I'm on KUbuntu 12.10, and I installed mysql 5.6 in ~/mysql/mysql. I also installed the g++ and libv8-dev packages using Ubuntu Software Center)

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
The `jsudf` UDF exposes MySQL's native User-defined function interface to the javascript runtime. Just like the `js` function, it expects the first argument to be a string containing a snippet of javascript. 

Unlike the `js` function, `jsudf` expects the script argument to be static (=the same for all rows). It compiles the script once, and runs it immediately. 

After running the script, `jsudf` then looks for a javascript function called `udf`. This `udf` function is then called for each row, and its return value is returned to the MySQL query.


