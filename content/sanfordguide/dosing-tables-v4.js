!function(e,t){"object"==typeof exports&&"object"==typeof module?module.exports=t():"function"==typeof define&&define.amd?define([],t):"object"==typeof exports?exports.DosingTable=t():e.DosingTable=t()}(self,(function(){return function(){"use strict"
var e={d:function(t,o){for(var s in o)e.o(o,s)&&!e.o(t,s)&&Object.defineProperty(t,s,{enumerable:!0,get:o[s]})},o:function(e,t){return Object.prototype.hasOwnProperty.call(e,t)}},t={}
let o
e.d(t,{default:function(){return m}})
let s=e=>{let t=URL.parse(e,o)
return"file://"===(window.frameElement?parent:window).location.origin&&t.origin===o?e.split("/").pop()+".html":t.href}
function a(e,t={},...o){let s=document.createElement(e)
for(let[e,o]of Object.entries(t))s.setAttribute(e,o)
if(o.length>1)for(let e of o)"object"!=typeof e&&(e=document.createTextNode(e)),s.appendChild(e)
else for(let e of o){"object"!=typeof e?s.innerHTML=e:s.appendChild(e)}return s}function i(e,t){let o=t?a("a",{href:s(t)},e):e
return a("td",{},o)}function n(e,t,o){let i=o?a("a",{href:s(o),class:"drugRowLink"},e):e,n=a("span",{},i)
return a("td",t,n)}function r(e,t,o,i){let n=o?a("a",{href:s(o),class:i?"topDrugGroupRowLink":"drugGroupRowLink"},e):e
return a("td",t,n)}function d(e,t,o){let i=t?a("a",{href:s(t),class:"modal-text-link"},e):e
return a("div",o,i)}function l(e,t,o){let i=o?a("a",{href:s(o),class:"drugRowLink"},e):e,n=a("td",{colspan:2},i)
return a("tr",t,n)}function h(e){const t=document.createElement("div")
t.innerHTML=e
const o=t.querySelectorAll("a[href]")
for(let e of o)e.setAttribute("href",s(e.getAttribute("href")))
const a=document.createDocumentFragment()
for(;t.firstChild;)a.appendChild(t.firstChild)
return a}function c(e){return e.length?" <sup>"+e.join(", ")+"</sup>":""}class u{constructor(e,t){this.json=e.data,this.drugs=t.data,this._initTableHeaders(),this._initTableRows()}getTableName(){return this.json.drug_table_metadata.drug_table_name??""}getTableHeaders(){return this.tableHeaders}getEditorialNote(){return this.json.drug_table_metadata.editorial_notes}getFootnotes(){return this.json.footnotes}getAbbreviations(){return this.json.abbreviations}getColumns(){return this.json.dosing_columns}getRows(){return this.rows}getRowById(e){return this.rows.find((t=>null!==t&&t.id===e))}_initTableHeaders(){this.tableHeaders=[]
let e=this.json.drug_table_metadata&&this.json.drug_table_metadata.drug_header||""
if(this.tableHeaders.push({headerString:e,headerUrl:""}),"object"==typeof this.json.dosing_columns)for(let e of this.json.dosing_columns){let t=void 0!==e.dc_display_name?e.dc_display_name:""
this.tableHeaders.push({headerString:t,headerUrl:e.dc_webedition_page_url})}this.tableHeaders.length<2&&this.tableHeaders.push({headerString:"",headerUrl:""})}_initTableRows(){this.rows=[],this.rowIdCount=0,this._addDrugGroups(this.json.drug_groups,1,[],[])}_addDrugGroups(e,t,o,s){for(let a of e){let e=o.concat(a.dg_headnotes??[]),i=this._combineArrays(s,a.footnotes)
if(void 0!==a.dg_name){let e=a.dg_name+c(a.footnotes||[])
this.rows.push({id:"header",col1:e,level:t,url:a.dg_webedition_page_url})}void 0!==a.drug_groups_drugs&&this._addDrugs(a.drug_groups_drugs,e,i),void 0!==a.children&&this._addDrugGroups(a.children,t+1,e,i)}}_addDrugs(e,t,o){let s=[]
for(let a of e){let e=this.drugs[a.drug_id]
if(void 0===e||void 0===e.drug_name)continue
let i=t.concat(a.dg_drug_headnotes??[]),n=this._combineArrays(o,a.footnotes),r=a.data,d=[e.drug_name,e.drug_short_name??"",a.dg_drug_descriptor??""].join(" ")
d+=c(a.footnotes||[]),s.push({id:this.rowIdCount++,col1:d,modalHeader:d,headnotes:i.filter((e=>e)),drugData:r,footnotes:n,url:e.drug_webedition_page_url})}this.rows.push(...s)}_combineArrays(e,t){return e=e??[],t=t??[],[...e,...t].filter(((e,t,o)=>o.indexOf(e)===t))}}class b{constructor(e,t){this.dosingTable=e,this.header=a("div",{class:"dosing-table-modal-header"},a("h4",{},"Editorial Note")),this.body=this.renderEditorialNote(t),this.content=a("div",{class:"dosing-table-modal"},this.body),this.close=a("button",{class:"dosing-table-modal-button"},"Close"),this.close.addEventListener("click",(()=>e.modal.hide())),this.footer=a("div",{class:"dosing-table-modal-footer"},this.close),this.dosingTable.modal.show(this.header,this.content,this.footer)}renderEditorialNote(e){let t=a("ul",{})
for(let o=0;o<e.length;o++){const s=a("li",{}),i=h(e[o.toString()])
s.appendChild(i),t.appendChild(s)}return t}}class g{constructor(e,t,o){this.dosingTable=e,this.row=this.dosingTable.data.getRowById(t),this.header=a("div",{class:"dosing-table-modal-header"},a("h2",{},this.row.modalHeader)),this.headnotes=this.row.headnotes??[],this.body=a("div",{}),this.footnotes=this.row.footnotes??[],this._renderModal(this.row,o),this.content=a("div",{class:"dosing-table-modal"},this.body),this.close=a("button",{class:"dosing-table-modal-button"},"Close"),this.close.addEventListener("click",(()=>e.modal.hide())),this.footer=a("div",{class:"dosing-table-modal-footer"},this.close),this.dosingTable.modal.show(this.header,this.content,this.footer)}_renderModal(e,t){this.body.innerHTML=null,this._renderHeadnotes()
let o=this.dosingTable.data.getColumns()
o=o[t-2].children
let s=this._buildModalRowArray(o,e.drugData,"table",0)
this._renderModalRows(s),this._renderAbbreviations(),this._renderFootnotes()}_renderHeadnotes(){for(let e of this.headnotes){const t=h(e)
this.body.appendChild(t)}}_buildModalRowArray(e,t,o,s){let a=[]
for(let i of e){let e=t[i.dc_id],n=i.dc_display_name+c(i.footnotes||[])
if(i.children.length>0){i.dc_presentation="checkbox"===i.dc_presentation?o:i.dc_presentation
let e=this._buildModalRowArray(i.children,t,i.dc_presentation,"table"===i.dc_presentation?s+1:s)
e.length>0&&(this._addFootnotes(i.footnotes),a.push({text:n,type:i.dc_presentation,url:i.dc_webedition_page_url,level:s}),a.push(...e))}else if(void 0!==e&&void 0!==e.dt_data_value)if(this._addFootnotes(i.footnotes),this._addFootnotes(e.footnotes),"checkbox"===i.dc_presentation&&"1"===e.dt_data_value){i.footnotes=this._combineArrays(i.footnotes,e.footnotes)
let t=i.dc_display_name+c(i.footnotes||[])
a.push({text:t,type:"table"===o?"checkbox:table":"checkbox:plain",url:i.dc_webedition_page_url})}else if("checkbox"!==i.dc_presentation){let t=e.dt_data_value.replace(/\n\r?/g,"<br />")+c(e.footnotes||[])
a.push({text:n,data:t,type:i.dc_presentation,url:i.dc_webedition_page_url})}}return a}_renderModalRows(e){let t=this._createNewModalTable(),o=!1
for(let s of e)switch(s.type){case"plain":case"bold":t.children.length>1&&(this.body.appendChild(t),t=this._createNewModalTable()),this.body.appendChild(d(s.text,s.url,{class:"plain"===s.type?"modal-plain-text":"modal-bold-text"})),void 0!==s.data&&this.body.appendChild(d(s.data,null,{class:"modal-plain-data-text"}))
break
case"table":void 0!==s.data?t.appendChild(this._renderTableRow(s.text,s.url,s.data,o)):t.append(l(s.text,this._getTableHeaderAttributes(s.level),s.url)),o=!o
break
case"checkbox:table":t.append(l(s.text,{class:o?"trOdd":"trEven",style:"text-indent:2px"},s.url)),o=!o
break
case"checkbox:plain":this.body.appendChild(d(s.text,s.url,{class:"modal-plain-data-text",style:"text-indent:2px"}))}t.children.length>1&&this.body.append(t)}_renderTableRow(e,t,o,s){return a("tr",{class:s?"trOdd":"trEven"},n(e,{},t),a("td",{},o))}_renderAbbreviations(){let e=this.body.innerText
for(let t of this.dosingTable.data.getAbbreviations())if(e.includes(t.abbreviation_identifier)){let e=a("p",{},t.abbreviation_text)
this.body.appendChild(e)}}_renderFootnotes(){let e=a("table",{class:"footnotes-table",style:"margin-top:20px"},"")
for(let t of this.dosingTable.data.getFootnotes()){if(!this.footnotes.includes(t.footnote_identifier))continue
let o=a("tr",{class:"footnotes-table-row"},""),s=a("span",{class:"footnote-identifier"},t.footnote_identifier),i=a("span",{class:"footnote-colon"},": "),n=a("td",{},"")
n.appendChild(s),n.appendChild(i)
let r=a("td",{width:"100%"})
const d=h(t.footnote_text)
r.appendChild(d),o.appendChild(n),o.appendChild(r),e.appendChild(o)}this.body.appendChild(e)}_createNewModalTable(){return a("table",{class:"modal-table",width:"100%",style:"margin-bottom:0px;"},a("colgroup",{},a("col",{style:"width: 50%"}),a("col",{style:"width: 50%"})))}_addFootnotes(e){for(let t in e)this.footnotes.includes(e[t])||this.footnotes.push(e[t])}_getTableHeaderAttributes(e){switch(e){case 0:return{class:"modalHeader",style:"background: linear-gradient(to bottom, rgba(1,87,155,1) 0%,rgba(0,0,0,1) 100%); color: white; font-style: bold"}
case 1:return{class:"modalHeader",style:"background:rgba(1,87,155,0.55)"}
case 2:return{class:"modalHeader",style:"background: rgba(1,87,155,0.35)"}
case 3:case 4:return{class:"modalHeader",style:"background: rgba(1,87,155,0.15)"}
default:return{class:"modalHeader",style:"background: rgba(1,87,155,0.10)"}}}_combineArrays(e,t){return e=e??[],t=t??[],[...e,...t].filter(((e,t,o)=>o.indexOf(e)===t))}}class p{constructor(e){this.dosingTable=e
let t=document.getElementById("normTitle")
t.innerHTML=e.data.getTableName()
let o=e.data.getEditorialNote()
if(Array.isArray(o)&&0!==o.length){let s=document.getElementById("editorialNote")
s.style.display="inline-block",s.addEventListener("click",(()=>new b(e,o))),t.innerHTML=""}let s=e.data.getTableHeaders()
this.columnCount=s.length
let n=document.getElementById("mainTableHeaders")
n.appendChild(this.makeColGroup())
let r=a("tr")
for(let e of s)r.appendChild(i(e.headerString,e.headerUrl))
n.appendChild(r)}renderMain(){let e=this.dosingTable.data.getRows(),t=!1,o=document.getElementById("mainTable")
o.innerText="",o.appendChild(this.makeColGroup())
for(let s of e){t=!t
let e,i=s.id,d=s.col1
if("header"===i){let t=["background: linear-gradient(to bottom, rgba(1,87,155,1) 0%,rgba(0,0,0,1) 100%); color: white; font-style: bold","background: rgba(1,87,155,0.55)","background: rgba(1,87,155,0.35)","background: rgba(1,87,155,0.15)","background: rgba(1,87,155,0.10)"],o=r(d,{},s.url,1===s.level)
e=a("tr",{class:"drugTableDrugGroup",style:t[Math.min(s.level,t.length)-1]},o)
for(let t=2;t<=this.columnCount;t++)e.appendChild(a("td"))}else{e=a("tr",{class:"tableRow",style:t?"background-color:white":"background-color:whitesmoke"},n(d,{},s.url))
for(let t=2;t<=this.columnCount;t++)e.appendChild(this.createCellWithButton(i,t))}o.appendChild(e)}}createCellWithButton(e,t){let o=a("a",{href:"javascript:;",class:"drugRowLink"},"View")
return o.addEventListener("click",(()=>new g(this.dosingTable,e,t))),a("td",{},o)}makeColGroup(){let e=a("colgroup"),t=(100/this.columnCount).toFixed(2)
for(let o=0;o<this.columnCount;o++)e.appendChild(a("col",{style:`width: ${t}%`}))
return e}}class f{constructor(){this.dialog=a("div",{class:"dosing-table-modal-dialog"}),this.container=a("div",{class:"dosing-table-modal-container"},this.dialog),this.container.addEventListener("click",(e=>{this.dialog.contains(e.target)||this.hide()})),this.hide(),document.body.append(this.container)}show(...e){!function(e){for(;e.hasChildNodes();)e.removeChild(e.firstChild)}(this.dialog)
for(let t of e)"object"!=typeof t?this.dialog.insertAdjacentHTML("beforeend",t):this.dialog.append(t)
this.container.style.display=""}hide(){this.container.style.display="none"}}class _{constructor(e){this.dosingTable=e,this.currentSearchTerm="",this.searchTextBox=document.getElementById("search"),this.searchTextBox.addEventListener("keyup",(()=>{this._searchTable(this.searchTextBox.value)})),document.getElementById("searchBtn").addEventListener("click",(()=>this.showModal())),this.searchTextBox2=a("input",{placeHolder:"Search this table",class:"search-input"}),this.searchTextBox2.addEventListener("keyup",(()=>{this._searchTable(this.searchTextBox2.value)})),this.body=a("div",{class:"search-body"},this.searchTextBox2),this.content=a("div",{},this.body),this.search=a("button",{class:"search-modal-button"},"Search"),this.search.addEventListener("click",(()=>e.modal.hide())),this.close=a("button",{class:"search-modal-button"},"Cancel"),this.close.addEventListener("click",(()=>this._clearSearch())),this.footer=a("div",{class:"search-modal-footer"},this.search,this.close)}showModal(){this.dosingTable.modal.show(this.content,this.footer),this.searchTextBox2.focus()}_searchTable(e){if("uuddlrlrba"===e)return void this.dosingTable.showDebugInfo()
this.currentSearchTerm=e
let t=document.querySelectorAll("tr.tableRow"),o=e.trim().replace(/ +/g," ").toLowerCase(),s=!1
for(let e=0;e<t.length;e++){~t[e].textContent.toLowerCase().indexOf(o)?(t[e].style.display="table-row",t[e].style.backgroundColor=s?"#f5f5f5":"#ffffff",s=!s):t[e].style.display="none"}this._syncSearchBoxes(e)}_syncSearchBoxes(e){this.searchTextBox.value=e,this.searchTextBox2.value=e
let t=document.getElementsByClassName("drugTableDrugGroup")
for(let e=0;e<t.length;e++)this.currentSearchTerm&&0!==this.currentSearchTerm.length?t[e].style.display="none":t[e].style.display="table-row"}_clearSearch(){this.searchTextBox.value="",this.searchTextBox2.value="",this._searchTable(""),this.dosingTable.modal.hide()}}var m=class{constructor({link_host:e}){return this.link_host=e,o=e,this.modal=new f(this),this.search=new _(this),this.identifier=(location.hash||"#dosing-table-data").substring(1),document.getElementById("mainTable").innerText=`Loading data for Table ${this.identifier}...`,void 0===window.table_data&&document.body.append(a("script",{src:`${this.identifier}.js`})),void 0===window.drugs&&document.body.append(a("script",{src:"dosing-table-drugs.js"})),this.afterFetch(),this}afterFetch(){"object"==typeof window.table_data&&"object"==typeof window.drugs?(this.data=new u(window.table_data,window.drugs),document.title=this.data.getTableName(),this.tableview=new p(this),this.tableview.renderMain()):window.setTimeout((()=>this.afterFetch()),100)}showDebugInfo(){let e=[["Identifier",this.identifier],["Origin",window.location.origin],["Link Host",this.link_host],["Drugs",Object.keys(this.data?.drugs||[]).length],["Rows",(this.data?.rows||[]).length],["Build Date","2025-04-22T15:44:27.344Z"]].map((e=>a("tr",{},a("th",{},e[0]),a("td",{},e[1])))),t=a("table",{},...e)
this.modal.show(t)}}
return t=t.default}()}))
