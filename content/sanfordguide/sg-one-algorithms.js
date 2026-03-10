(()=>{var e={d:(t,n)=>{for(var l in n)e.o(n,l)&&!e.o(t,l)&&Object.defineProperty(t,l,{enumerable:!0,get:n[l]})},o:(e,t)=>Object.prototype.hasOwnProperty.call(e,t)},t={};(()=>{"use strict"
e.d(t,{default:()=>n})
const n=class{constructor(e){let t=[],n=function(e){let t=[],n=function(e){let t=[],n=0,l=0,i=!1
for(let r=0;r<e.length;r++){let s=e[r],d=e[r+1]
t[n]=t[n]?t[n]:[],t[n][l]=t[n][l]?t[n][l]:[],'"'===s&&i&&'"'===d?(t[n][l]+=s,r++):'"'!==s?","!==s||i?"\r"!==s||"\n"!==d||i?"\r"!==s&&"\n"!==s||i?t[n][l]+=s:(n++,l=0):(n++,l=0,r++):l++:i=!i}return t}(e),i=function(e){if(0===e.length)return".csv file cannot be empty"
for(let t in e)if(e.hasOwnProperty(t)&&2!==e[t].length&&3!==e[t].length)return"Row "+(t+1)+" is invalid."
return null}(n)
if(i)return void alert(i)
for(let e=0;e<n.length;e++)t.push(l(n[e]))
return t}(e)
function l(e){if(!e||0===e.length||0===e[0].length)return
let t={}
return t.id=e[0],t.text=e[1],t.pointsTo=3===e.length&&e[2].length>0?e[2].split(";"):[],t}function i(e,n){let l=r(e.id,"sg1a-question",e.text),s=r("answers"+e.id,"sg1a-answers")
e.pointsTo.forEach((n=>{!function(e,n,l){let s=document.createElement("button")
s.setAttribute("type","button"),s.setAttribute("id",e.id),s.setAttribute("class","sg1a-answer"),s.addEventListener("click",(()=>function(e,n){let l=document.getElementById("selectedAnswer"+n),s=l.lastElementChild
for(;s;)l.removeChild(s),s=l.lastElementChild
let d=document.getElementById("answers"+n),o=d.children
for(let t=0;t<o.length;t++){let n=o[t],l=n.getAttribute("id")===e
n.setAttribute("class","sg1a-answer "+(l?"sg1a-answer-selected":"sg1a-answer-not-selected"))}let a=t[e],u=t[a.pointsTo[0]]
u.pointsTo.length>0?i(u,l):function(e,t){let n=r(e.id,"endState",e.text)
t.appendChild(n)}(u,l)}(e.id,l))),s.innerHTML=e.text,n.appendChild(s)}(t[n],s,e.id)})),l.appendChild(s)
let d=r("selectedAnswer"+e.id,"sg1a-answers")
l.appendChild(d),n.appendChild(l)}function r(e,t){let n=arguments.length>2&&void 0!==arguments[2]?arguments[2]:null,l=document.createElement("div")
if(l.setAttribute("id",e),l.setAttribute("class",t),n){let e=document.createElement("div")
e.innerHTML=n,l.appendChild(e)}return l}!function(e){e.forEach((e=>{t[e.id]=e}))}(n),i(n[0],document.getElementById("algo"))}}})(),DisplayAlgorithm=t.default})()
