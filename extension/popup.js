const STLDS=["xyz","tk","ml","ga","cf","gq","pw","top","click","win","loan"];
const SWORD=["login","secure","banking","account","verify","update","signin","password","confirm"];
const BRAND=["paypal","amazon","netflix","microsoft","apple","bank","fedex","facebook","instagram"];
const TRUST=["google.com","youtube.com","facebook.com","instagram.com","twitter.com","github.com","microsoft.com","apple.com","amazon.com","netflix.com","linkedin.com","wikipedia.org","reddit.com","stackoverflow.com"];

function trusted(url){return url.startsWith("https")&&TRUST.some(d=>url.toLowerCase().includes(d));}

function analyze(url){
  const u=url.toLowerCase();
  let score=0,sigs=[];
  if(trusted(url))return{score:0.03,sigs:["✅ Verified trusted domain — Safe"]};
  if(!url.startsWith("https")){score+=0.20;sigs.push("🔓 No HTTPS encryption");}
  if(url.includes("@")){score+=0.25;sigs.push("⚠️ @ symbol in URL");}
  if(/(\d{1,3}\.){3}\d{1,3}/.test(url)){score+=0.25;sigs.push("🖥️ IP address as domain");}
  const tld=STLDS.find(t=>u.includes("."+t));
  if(tld){score+=0.30;sigs.push("🌐 High-risk TLD: ."+tld);}
  if(["bit.ly","tinyurl","goo.gl","t.co"].some(s=>u.includes(s))){score+=0.20;sigs.push("🔀 Shortened URL");}
  if(SWORD.some(w=>u.includes(w))){score+=0.10;sigs.push("🔑 Sensitive word in URL");}
  const b=BRAND.find(b=>u.includes(b));
  if(b&&!trusted(url)){score+=0.20;sigs.push("🏢 Brand impersonation: "+b);}
  if((url.match(/-/g)||[]).length>3){score+=0.10;sigs.push("➖ Too many hyphens");}
  if(url.length>100){score+=0.10;sigs.push("🔗 Very long URL: "+url.length+" chars");}
  return{score:Math.min(score,1.0),sigs:sigs.length?sigs:["✅ No major risk indicators"]};
}

function getLevel(s){
  if(s<0.30)return{lv:"SAFE",      em:"✅",col:"#00ff88",bg:"rgba(0,255,136,0.15)"};
  if(s<0.60)return{lv:"SUSPICIOUS",em:"⚠️",col:"#ffcc00",bg:"rgba(255,204,0,0.15)"};
  return          {lv:"DANGEROUS", em:"🚨",col:"#ff2d55",bg:"rgba(255,45,85,0.15)"};
}

document.addEventListener("DOMContentLoaded",()=>{
  chrome.tabs.query({active:true,currentWindow:true},(tabs)=>{
    document.getElementById("urlBox").textContent=tabs[0]?.url||"No URL";
  });

  document.getElementById("btn").addEventListener("click",()=>{
    const btn=document.getElementById("btn");
    const loading=document.getElementById("loading");
    const result=document.getElementById("result");

    chrome.tabs.query({active:true,currentWindow:true},(tabs)=>{
      const url=tabs[0]?.url||"";
      if(!url||url.startsWith("chrome://")||url.startsWith("edge://")){
        alert("Cannot scan this page!");return;
      }

      btn.disabled=true;
      btn.textContent="Analyzing...";
      loading.style.display="block";
      result.style.display="none";

      setTimeout(()=>{
        const{score,sigs}=analyze(url);
        const{lv,em,col,bg}=getLevel(score);
        const pct=Math.round(score*100);

        document.getElementById("score").textContent=pct+"%";
        document.getElementById("score").style.color=col;
        document.getElementById("badge").textContent=em+" "+lv;
        document.getElementById("badge").style.cssText="padding:5px 12px;border-radius:20px;font-size:11px;font-weight:800;letter-spacing:1px;background:"+bg+";color:"+col+";border:1px solid "+col;
        document.getElementById("bar").style.width=pct+"%";
        document.getElementById("bar").style.background=col;
        document.getElementById("signals").innerHTML=sigs.slice(0,5).map(s=>"<div class='signal'>"+s+"</div>").join("");
        result.style.display="block";
        btn.disabled=false;
        btn.textContent="⚡ SCAN THIS PAGE";
        loading.style.display="none";
      },800);
    });
  });
});
