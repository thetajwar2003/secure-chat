    Computer Security Project: Secure(?) Chat code{white-space: pre-wrap;} span.smallcaps{font-variant: small-caps;} span.underline{text-decoration: underline;} div.column{display: inline-block; vertical-align: top; width: 50%;} div.hanging-indent{margin-left: 1.5em; text-indent: -1.5em;} ul.task-list{list-style: none;} pre > code.sourceCode { white-space: pre; position: relative; } pre > code.sourceCode > span { display: inline-block; line-height: 1.25; } pre > code.sourceCode > span:empty { height: 1.2em; } code.sourceCode > span { color: inherit; text-decoration: inherit; } div.sourceCode { margin: 1em 0; } pre.sourceCode { margin: 0; } @media screen { div.sourceCode { overflow: auto; } } @media print { pre > code.sourceCode { white-space: pre-wrap; } pre > code.sourceCode > span { text-indent: -5em; padding-left: 5em; } } pre.numberSource code { counter-reset: source-line 0; } pre.numberSource code > span { position: relative; left: -4em; counter-increment: source-line; } pre.numberSource code > span > a:first-child::before { content: counter(source-line); position: relative; left: -1em; text-align: right; vertical-align: baseline; border: none; display: inline-block; -webkit-touch-callout: none; -webkit-user-select: none; -khtml-user-select: none; -moz-user-select: none; -ms-user-select: none; user-select: none; padding: 0 4px; width: 4em; color: #aaaaaa; } pre.numberSource { margin-left: 3em; border-left: 1px solid #aaaaaa; padding-left: 4px; } div.sourceCode { } @media screen { pre > code.sourceCode > span > a:first-child::before { text-decoration: underline; } } code span.al { color: #ff0000; font-weight: bold; } /\* Alert \*/ code span.an { color: #60a0b0; font-weight: bold; font-style: italic; } /\* Annotation \*/ code span.at { color: #7d9029; } /\* Attribute \*/ code span.bn { color: #40a070; } /\* BaseN \*/ code span.bu { } /\* BuiltIn \*/ code span.cf { color: #007020; font-weight: bold; } /\* ControlFlow \*/ code span.ch { color: #4070a0; } /\* Char \*/ code span.cn { color: #880000; } /\* Constant \*/ code span.co { color: #60a0b0; font-style: italic; } /\* Comment \*/ code span.cv { color: #60a0b0; font-weight: bold; font-style: italic; } /\* CommentVar \*/ code span.do { color: #ba2121; font-style: italic; } /\* Documentation \*/ code span.dt { color: #902000; } /\* DataType \*/ code span.dv { color: #40a070; } /\* DecVal \*/ code span.er { color: #ff0000; font-weight: bold; } /\* Error \*/ code span.ex { } /\* Extension \*/ code span.fl { color: #40a070; } /\* Float \*/ code span.fu { color: #06287e; } /\* Function \*/ code span.im { } /\* Import \*/ code span.in { color: #60a0b0; font-weight: bold; font-style: italic; } /\* Information \*/ code span.kw { color: #007020; font-weight: bold; } /\* Keyword \*/ code span.op { color: #666666; } /\* Operator \*/ code span.ot { color: #007020; } /\* Other \*/ code span.pp { color: #bc7a00; } /\* Preprocessor \*/ code span.sc { color: #4070a0; } /\* SpecialChar \*/ code span.ss { color: #bb6688; } /\* SpecialString \*/ code span.st { color: #4070a0; } /\* String \*/ code span.va { color: #19177c; } /\* Variable \*/ code span.vs { color: #4070a0; } /\* VerbatimString \*/ code span.wa { color: #60a0b0; font-weight: bold; font-style: italic; } /\* Warning \*/ .display.math{display: block; text-align: center; margin: 0.5rem auto;} body { font-family:Gill Sans MT; color:#657b83; background-color:#fdf6e3; max-width:500pt; padding-left:25pt; padding-right:25pt; padding-bottom:20pt; margin:0 auto 0 auto; text-align:justify; } a:link {color:#6c71c4;} a:visited {color:#859900;} a:hover {color:#268bd2;} a:active {color:#d33682;} h1{} h2{border-style:solid; text-align:center; } h3 { margin-bottom:2pt; /\*color:#268bd2;\*/ font-weight:bold; } strong { color:#d33682; font-weight:bolder; } em { color:#268bd2; font-style:italic; font-weight:bolder; } code { background-color:#eee8d5; color:#586e75; } table.sourceCode { background-color:#eee8d5; color:#586e75; } pre.sourceCode { background-color:#eee8d5; color:#586e75; } .math { /\*background-color:#eee8d5;\*/ color:#586e75; font-family:Times New Roman; } /\*use a contextual style to undo the blue-ness:\*/ .math em { color:#586e75; font-weight:normal; } .descrip { max-width:500pt; padding-left:25pt; text-align:justify; } .descripbig { max-width:575pt; padding-left:0pt; text-align:justify; } .emph { color:#d33682; font-weight:bolder; } .litem { color:#268bd2; font-style:italic; font-weight:bolder; } .hl { color:#268bd2; font-style:italic; } .required { color:#268bd2; font-style:italic; font-weight:bold; } .inputbox { background-color:#eee8d5; color:#586e75; font-family:Gill Sans MT; font-weight:bolder; }

# Computer Security Project: Secure(?) Chat

## _Due:_ Wednesday, May 8th @ 11:59pm

## Synopsis

Write a chat program in C that provides:

- Authentication of correspondents
- Message secrecy (encryption)
- Message integrity (MACs)

Given that this program processes formatted input from a network, you should naturally focus on software security as well.

### Goals for the student

- Gain familiarity using cryptographic libraries (`openssl`).
- Experience in protocol design.
- Understanding various issues in network programming.
- How to avoid common software security issues.

## Important Notes

If you’d like, feel free to collaborate in small groups ( ≤ 3 members). If you do collaborate in a group, please **use git**. This ought to help you organize, but it will also be useful for me to make sure everyone was contributing to the project. If you have not collaborated with git much, I have some maybe helpful notes [here](http://www-cs.ccny.cuny.edu/~wes/CSC103/scm.html#collaborate).

## Details

I’ve given you a skeleton which does very basic chat stuff: Depending on the invocation, it will listen for connections, or make one with another host. Beyond that, it just sends and receives text, displaying each message in a log window. It will be up to you to:

- Write some sort of handshake protocol to setup ephemeral keys (your protocol should have [perfect forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy)!).
- Mutual authentication, using public key cryptography.
- After authentication, each message should be encrypted and tagged with a message authentication code. You may also want to take measures to prevent replay attacks.

I think [SSH](https://en.wikipedia.org/wiki/Ssh) will be a good model on which to base your protocol. In particular, don’t use PKI (public-key infrastructure, with certificates and such), and instead assume that communicating parties have already exchanged public keys. However, implementing deniable authentication would be a nice touch (and is something SSH does not provide). If you want to use 3DH, you can find an example in `dh-example.c`.

### Compiling the skeleton

You will need:

- [gtk3](https://en.wikipedia.org/wiki/Gtk) and the header files. If you are on linux/BSD, you might have to get a package like `gtk+3-devel` or similar, although some distributions (e.g. Arch Linux) will include header files in the normal package (no `-devel` needed).
- [openssl](http://www.openssl.org/) and headers (`openssl-devel`).
- [gmp](http://gmplib.org/) and its header files (`gmp-devel`).

Running `make` should just work on most linux or BSD systems if you have all the above installed, but let me know. I’m confident you could also get this working just fine on a mac via [homebrew](https://brew.sh/). You should be able to get it working on Windows as well, but it might be easier to just do it in a virtual machine. If you do get it working natively on Windows, I’d be interested, so please let me know what steps were needed.

Once you do have the skeleton compiled, you can run `./chat -h` and see a list of options. You should be able to test it out like this:

    $ ./chat -l & sleep 1 && ./chat -c localhost &

Two windows should appear in a moment, connected over the loopback interface.

### Other notes

There is a directory `openssl-examples` that demonstrates how to get most of the functionality you’ll need from `openssl`. However, your professor decided to write his own Diffie-Hellman key exchange, as the openssl version was somehow even more obfuscated and confusing than usual. You can see the Diffie-Hellman stuff in files `dh.h`,`dh.c`, and you can see some example usage in `dh-example.c`. Note that the function `dhFinal(...)` will also do key derivation for you (transforming the Diffie-Hellman value into pseudorandom bits that you can use as keys for encryption and MACs).

You might also find the following links helpful.

- [network programming guide](https://beej.us/guide/bgnet/)
- If you ever need to manipulate `mpz_t` types, read `info gmp`. Alternatively, you can read [the manual online](https://gmplib.org/manual/).

## Submission Procedure

Have one of your group members send me your repository. If you have it hosted somewhere, you can just send a link, but if you’ve done things on your own servers, just make me an archive like this:

    $ cd /path/to/your/chat/../
    $ tar -czf chat.tgz chat/

Importantly, there should be a `.git/` folder in there containing the commit history.
