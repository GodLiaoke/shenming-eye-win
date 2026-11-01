const {readFileSync}=require('node:fs');const {join}=require('node:path');const vm=require('node:vm');const assert=require('node:assert/strict');const {test}=require('node:test');
function fixture(path=process.env.PHOENIX_TEST_SIDEBAR||join(__dirname,'../src/sidebar.html')) {
 const html=readFileSync(path,'utf8');const sent=[];const elements=new Map();
 function node(){return {value:'',disabled:false,textContent:'',innerHTML:'',style:{},children:[],classList:{add(){},remove(){},toggle(){}},querySelector(){return this.led??=node()}};}
 const doc={getElementById(id){if(!elements.has(id))elements.set(id,node());return elements.get(id)},body:node()};doc.getElementById('modes').children=[node(),node(),node()];
 const window={ipc:{postMessage(s){sent.push(JSON.parse(s))}},addEventListener(){}};
 const ctx=vm.createContext({document:doc,window,confirm:()=>true,setTimeout(){},navigator:{clipboard:{async writeText(){}}}});
 const script=html.match(/<script>([\s\S]*?)<\/script>/)[1].replace('__BOOT__',JSON.stringify({phase:'license',message:'',build:'fixture-build',version:'1.2.1'}));vm.runInContext(script,ctx);
 return {ctx,window,sent,$:id=>doc.getElementById(id),update:window.phoenixUpdate};
}
const ready={phase:'ready',nodeUri:'socks5://test:test@192.168.1.2:2025',qrSvg:'<svg/>',nodeMeta:'local',address:'192.168.1.2:2025',captureError:null};
test('empty-error login always enables activation',()=>{const f=fixture();f.$('activateBtn').disabled=true;f.update({phase:'license',message:''});assert.equal(f.$('activateBtn').disabled,false)});
test('Enter and repeated click cannot submit duplicate activation',()=>{const f=fixture();f.$('cardInput').value='valid-card';vm.runInContext('activate();activate()',f.ctx);assert.equal(f.sent.length,1)});
test('forget clears QR, node URI, metadata and clients',()=>{const f=fixture();f.update({...ready,clients:3});f.update({phase:'license',message:'forgot',clearCard:true});assert.equal(f.$('qrWrap').style.display,'none');assert.equal(f.$('qrWrap').innerHTML,'');assert.equal(f.$('nodeMeta').textContent,'节点尚未启动');assert.equal(f.$('clientLabel').textContent,'UDP 转发 · 0 台设备');assert.equal(vm.runInContext('state.nodeUri',f.ctx),'')});
test('forget clears entered card',()=>{const f=fixture();f.$('cardInput').value='old-card';f.update({phase:'license',clearCard:true});assert.equal(f.$('cardInput').value,'')});
test('service error hides old QR',()=>{const f=fixture();f.update(ready);f.update({phase:'service-error',message:'failed'});assert.equal(f.$('qrWrap').style.display,'none')});
test('storage failure remains a ready grant and is explained',()=>{const f=fixture();f.update({...ready,storageWarning:'本次已激活，未持久化'});assert.equal(f.$('statusMain').textContent,'实时接收已启动');assert.equal(f.$('captureWarn').textContent,'本次已激活，未持久化')});
test('driver failure leaves only SOCKS mode ready',()=>{const f=fixture();f.update({...ready,captureError:'Win32 5'});const leds=f.$('modes').children.map(n=>n.querySelector('.mode-led').style.background);assert.deepEqual(leds,['','','var(--cyan)']);assert.equal(f.$('captureWarn').style.display,'block')});
test('footer reflects compiled version and build',()=>{const f=fixture();assert.equal(f.$('buildLabel').textContent,'v1.2.1 · 构建 fixture-build')});
