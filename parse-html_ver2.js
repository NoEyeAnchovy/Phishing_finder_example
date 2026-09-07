const fs=require('fs');
const cheerio=require('cheerio');
const url=require('url');
const html=fs.readFileSync("mal4.html",'utf-8');
const $=cheerio.load(html);
var action;
var js;
var click;
var jq_ok;
action=[];
jq_ok=[];
js=[];
click=[];
img_src=[];
a_href=[];
console.log(action.length)
$('form').each((i,el)=>{
    var a=$(el).attr('action');
    if(a!==undefined)
        action.push(a)
    //console.log(action)
});
$('script').each((i,el)=>{
   if($(el).attr('src')!=null)
   {
    jq_ok.push($(el).attr('src'))
   }
    js.push($(el).html())//수정 필요. 지금 방식으로는 맨 마지막 html만 들어가게 될 것임. 
});
$('button').each((i,el)=>{
    var a=$(el).attr('onclick');
    if(a!==undefined)
        click.push(a)
   
});
$('img').each((i,el)=>{
   if($(el).attr('src')!=null)
   {
    img_src.push($(el).attr('src'))
   }
});
$('a').each((i,el)=>{
   if($(el).attr('href')!=null)
   {
    a_href.push($(el).attr('href'))
   }
});
console.log(js);
//console.log(click)
//console.log(jq_ok);
//console.log(action);
//console.log(action.length)
for(var i=0;i<action.length;i++)
{
    var answer2=url_sus(action[i]);
    console.log("were there suspicious actions? : "+answer2);
}
for(var i=0;i<js.length;i++)
{
    var answer3=check_all(js[i]);
    console.log("were there suspicious urls? : "+answer3);
    console.log("was suspicious request found? : "+find_sus_req(js[i]));
    console.log("is there any dangerous hardcoded strings? : "+find_hardcode(js[i]));
    console.log("is there any dangerous strings? : "+find_string_and_judge(js[i]));
    console.log("is there any dangerous functions? : "+find_click(js[i]));
}
var cmt=parse_cmt(html);
//console.log(cmt)
console.log("were there suspicious comments? : "+find_sus_cmt(cmt));
var title=parse_title(html);
console.log("was suspicious char found? : " + find_sus_char(title));
for(var i=0;i<jq_ok;i++)
{
    console.log(jq_ok[i]);
    console.log("is jquery used? : "+find_jq(jq_ok[i]))
}
// 안전하게 hostname을 추출하는 함수
function get_hostname(url_string) {
    try {
        // 'http'나 'https' 같은 프로토콜이 없으면 파싱이 실패하므로, 임시로 'http://'를 붙여줍니다.
        // 이는 <form action>에 '/path/to/script.php' 같이 상대 경로만 들어있는 경우를 대비합니다.
        // 하지만 피싱 사이트는 대개 외부 URL을 사용하므로, 프로토콜이 없는 경우 'null'을 반환하여 분석하지 않도록 합니다.

        // 만약 URL이 'http'나 'https'로 시작하지 않으면 (예: /login.php), 현재 도메인을 분석할 수 없으므로 null을 반환합니다.
        if (!url_string.startsWith('http')) {
            return null; 
        }

        // URL 클래스를 사용하여 호스트 이름 추출 (이것이 가장 안전합니다)
        const parsedUrl = new URL(url_string);
        return parsedUrl.hostname.replace(/^www\./, ''); // 'www.'를 제거하여 비교 용이하게 함

    } catch (e) {
        // 유효하지 않은 URL 문자열일 경우 (예외 처리)
        // console.error("URL 파싱 오류:", url_string, e.message); 
        return null;
    }
}
function is_external(current_url, sus_url) {
    const current_hostname = get_hostname(current_url);
    const sus_hostname = get_hostname(sus_url);

    // 둘 중 하나라도 유효한 호스트네임을 추출할 수 없으면 (예: 상대 경로), 외부 링크로 판단하기 어려우므로 false 반환
    if (!current_hostname || !sus_hostname) {
        return false; 
    }
    
    // ⭐ 중요: 서브도메인 관계를 고려하여 루트 도메인만 비교
    // 예: 'naver.com'과 'nid.naver.com'은 같은 도메인으로 간주해야 합니다.
    const current_root = current_hostname.split('.').slice(-2).join('.'); 
    const sus_root = sus_hostname.split('.').slice(-2).join('.');

    // 루트 도메인이 다르면 완전히 다른 외부 링크입니다.
    if (current_root !== sus_root) {
        console.log(`[외부 링크] 현재(${current_root})와 의심(${sus_root}) 도메인이 다릅니다.`);
        return true; 
    }
    
    // 루트 도메인이 같으면 (예: naver.com), 외부가 아닙니다.
    return false;
}
function get_current_url()
{
    return "https://login.example.invalid";//나중에 확장 프로그램으로 만들 시 고칠 것. 지금은 url을 감지할 방법이 없음
}
function url_sus(sus_url)
{
    const sus_domain=['.php','.jsp','.pl','.asp','.cgi','.web.app','.firebaseapp.com'];
    const current_url=get_current_url();
    var pattern=/http[/S]*/g;
    var tf=current_url.match(pattern);
    if(tf==null)
    {
        var decode_url=Buffer.from(sus_url,'base64').toString('utf8');
        tf=decode_url.match(pattern);
        if(tf==null)
        {
            return false;
        }
        else
        {
            sus_url=decode_url.toString();
        }
    }
    //if(is_external(current_url,sus_url))
    //{
     //   return true;
    //}
    const isCriticalDomain = sus_domain.some(d => sus_url.includes(d));
    if(isCriticalDomain==true)
        return true;
    var parm_pattern=/\?[\s\S]*=[\s\S]*[&]?/g;
    var answer=sus_url.match(parm_pattern)
    //console.log("this is the token : "+answer);
    if(answer!=null)
    {
        var ifsus=find_sus_string(answer.toString());
        if(ifsus==true)
            return true;
    }
    return false;
}
function find_click(js)//나중에 전체 script 검사로 바꾸는 게 좋아 보임. 
{
    const script=js;
    const sus_func=['.ajax','.post','.get'];
    var sus=sus_func.some(d=>script.includes(d));
    var parsed_url;
    if(sus==true)
    {
        const urlPattern = /url\s*:\s*['"](http[^'"]+)['"]/g;
        const match = script.match(urlPattern);

        if (match) {
            for(var i=0;i<match.length;i++)
            {
                var parsed_url = match[i]; // match[1]에는 캡처된 URL 문자열이 들어갑니다.
                console.log(`[추출된 URL]: ${parsed_url}`);
        
                var real_sus=url_sus(parsed_url);
                if(real_sus==true)
                {
                    return true;
                }
            }
        }
        return false;
    }
    return false;
}
function parse_cmt(doc)//주석을 파싱하는 코드. 
{
    const pattern=/<\!--[\s\S]*?-->/g;//html 주석
    const match=doc.match(pattern);
    //console.log(match);
    const pattern2=/\/\/[\s\S]*?[\n]/g;//자바스크립트 주석
    const match2=doc.match(pattern2)
    if(match)
        return match.concat(match2)
    else if(match2)
        return match2;
    else
        return null;
}
function find_sus_cmt(cmt)//수싱한 주석 판정, 가끔 작동 안함 왠진 모름
{
    const sus_list=["injection"];
    for(var i=0;i<cmt.length;i++)
    {
        var issuscmt = sus_list.some(d => cmt[i].includes(d));
        if(issuscmt==true)
            return true;
    }
    return false;
}
function extractBlock(js, keyword)
{
    let idx = js.indexOf(keyword);
    if (idx < 0) return null;

    // keyword 이후 첫 '{' 찾기
    let braceStart = js.indexOf("{", idx);
    if (braceStart < 0) return null;

    let count = 0;
    for (let i = braceStart; i < js.length; i++)
    {
        if (js[i] === "{") count++;
        else if (js[i] === "}") count--;

        if (count === 0)
            return js.substring(braceStart, i + 1);
    }

    return null; // 끝까지 못 닫았으면 이상한 코드
}

function find_sus_req(js)/////////////////////의존성 관련 수정 필요/////////////////////////////
{
    const sus_func = ['ajax', 'post', 'get'];
    let sus = sus_func.some(d => js.includes(d));
    if (!sus) return false;

    let okfunc = extractBlock(js, "success");
    if (!okfunc) return true; // 성공 처리 없음

    let errfunc = extractBlock(js, "error");
    if (!errfunc) return true; // 에러 처리 없음

    //console.log(okfunc);
    //console.log(errfunc);

    // TODO: okfunc / errfunc 내부 동작 분석
    var argv=extractargv(js,"success");
    var danger=okfunc.includes(argv);
    if(danger==false)
        return true;
    //errfunc 내부 동작 분석 필요
    return false;
}
function parse_title(html)
{
    var title;
    $('title').each((i,el)=>{
            title=$(el).text();
    });
    //console.log(title);
    return title;
}
function find_sus_char(title)
{
    var kiril=/[\u0400-\u04ff]/g;
    var greek=/[\u0370-\u03ff]/g;
    var find1=title.match(kiril);
    var find2=title.match(greek);
    //console.log(find2);
    if(find1==null || find2==null)
    {
        return true;
    }
    return false;
}
function find_jq(jq_lib)
{
    const sus_lib=['jquery.min.js','jquery'];
    let sus = sus_lib.some(d => jq_lib.includes(d));
    if (!sus) return false;
    else return true;

}
function find_sus_string(sus_string)
{
    if(typeof sus_string==='string')
    {
        var sus_param=sus_string.split('=');
        if(sus_param.length==1)//그냥 문자열이 들어온 경우
            sus_param=sus_param[0];
        else//쿼리 형태로 들어온 경우
            sus_param=sus_param[1];
        console.log(sus_param);
        if(sus_param.length>15)//이 정도를 마지노선으로 봄
        {
            return true;
        }
        else
            return false;
    }
    else
        console.log("wrong type");
}
function check_all(js)
{
    const urlPattern = /['"](http[^'"]+)['"]/g;
    const match = js.match(urlPattern);

    if (match) {
        for(var i=0;i<match.length;i++)
        {
            var parsed_url = match[i]; // match[1]에는 캡처된 URL 문자열이 들어갑니다.
            console.log(`[추출된 전체 URL]: ${parsed_url}`);
            var answer=url_sus(parsed_url);
            return answer;
        }
    }
    return false;
}
function find_hardcode(js)
{
    var sus_func=["pushState","replaceState"];
    var argv;
    let sus = sus_func.some(d => js.includes(d));
    if (!sus) return false;
    for(var i=0;i<sus_func.length;i++)
    {
        var find=extractargv(js,sus_func[i]);
        if(find!=null)
            argv=find;
    }
    //console.log(argv);
    if(argv!=null)
    {
        argv=argv.toString().replace(/[\n]\s*/g,'');//엔터랑 공백 제거
        argv=argv.toString().replace(/"/g,'');//큰따옴표 제거
        argv=argv.toString().split(',');
        //console.log(argv);
        for(var i=0;i<argv.length;i++)
        {
            var result=find_sus_string(argv[i]);
            if(result==true)
                return true;
        }
    }
    return false;
}
function find_string_and_judge(js)//////////////////변수 안의 문자열 찾기/////////////////////////////////
{
    var pattern=/["'][\s\S]+["'];/g;
    var match=js.match(pattern);
    if(match==null)
        return false;
    for(var i=0;i<match.length;i++)
    {
        match[i]=match[i].toString().replace(/"/g,'');//큰따옴표 제거
        match[i]=match[i].replace(';','');
        //console.log("match is " + match[i]);
        var a=find_sus_string(match[i].split('=')[0]);///base64 대비
        if(a==true)//base64가능성 있음
        {
            var decode=Buffer.from(match[i].toString(),'base64').toString('utf8');
            //console.log(decode)
            var answer2=check_all(decode);
            var answer=url_sus(decode);
            console.log("is decoded url there? : "+answer);
            console.log("is decoded js there? : "+answer2);
            return true;
        }
    }
    return false;
}
