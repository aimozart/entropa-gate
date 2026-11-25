(function(){
"use strict";
var WASM_B64="@WASM_B64@";
var SENTENCE={0:"Verified: every signature, proof and hash in this bundle checks out.",1:"Refused: this file is not a valid bundle.",2:"Refused: this bundle does not verify. Something in it was changed or does not match its signatures.",3:"Refused: this file is larger than 5 MiB.",4:"Refused: the checker stopped before it could finish."};
var LABEL={records:"Records",checkpoints:"Signed checkpoints",receipts:"Receipts",consistency:"Consistency proofs",witnesses:"Witness statements",signatures:"Signatures"};
var res=document.getElementById("result"),verdict=document.getElementById("verdict"),counts=document.getElementById("counts"),input=document.getElementById("file");
var ready=null;
function load(){
  if(ready)return ready;
  var bin=atob(WASM_B64),b=new Uint8Array(bin.length);
  for(var i=0;i<bin.length;i++)b[i]=bin.charCodeAt(i);
  ready=WebAssembly.instantiate(b,{}).then(function(r){return r.instance.exports;});
  return ready;
}
function show(code,json){
  res.setAttribute("data-code",String(code));
  verdict.textContent=SENTENCE[code]||SENTENCE[4];
  counts.textContent="";counts.hidden=true;
  if(code===0&&json){
    Object.keys(LABEL).forEach(function(k){
      var dt=document.createElement("dt"),dd=document.createElement("dd");
      dt.textContent=LABEL[k];dd.textContent=String(json[k]);counts.appendChild(dt);counts.appendChild(dd);
    });
    counts.hidden=false;
  }
}
function check(bytes){
  return load().then(function(x){
    var p=x.input_reserve(bytes.length);
    new Uint8Array(x.memory.buffer,p,bytes.length).set(bytes);
    var code=x.verify();
    var out=new Uint8Array(x.memory.buffer,x.output_ptr(),x.output_len());
    var json=null;try{json=JSON.parse(new TextDecoder().decode(out));}catch(e){}
    show(code,json);
  });
}
input.addEventListener("change",function(){
  var f=input.files&&input.files[0];if(!f)return;
  verdict.textContent="Checking...";res.setAttribute("data-code","");counts.hidden=true;
  f.arrayBuffer().then(function(ab){return check(new Uint8Array(ab));}).catch(function(){show(4,null);});
});
})();
