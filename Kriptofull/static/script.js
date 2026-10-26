(() => {
'use strict';
const $ = id => document.getElementById(id);
const nav = document.querySelectorAll('[data-page]');
const HEX = s => /^[0-9a-f\s]+$/i.test(s.trim());
const enc = new TextEncoder();
const decoder = new TextDecoder('utf-8',{fatal:false});
const state = {config:null,current:'home',textLast:null,textLastName:'', textLoaded:false,
  encryptFile:null,decryptFile:null,decryptOriginal:null, compareFile:null,feistelFile:null,
  encryptResult:null,decryptResult:null,encryptConfig:null};
const ctx = ['text','encrypt-file','decrypt-file','compare','feistel'];
const enumAlg = ['DES','3DES','AES-128','AES-192','AES-256'];
const modes = ['ECB','CBC','GCM'];
const choice = {
  text: {algorithm:'DES',mode:'CBC',engine:'own'},
  'encrypt-file': {algorithm:'DES',mode:'CBC',engine:'own'},
  'decrypt-file': {algorithm:'DES',mode:'CBC',engine:'own'},
  compare: {algorithm:'DES',mode:'CBC',engine:'own'},
  feistel: {algorithm:'DES',mode:'ECB',engine:'own'}
};
let toastTimer;
function showToast(message,error=false){
  const t=$('toast');t.textContent=message;t.className='toast show'+(error?' error':'');clearTimeout(toastTimer);toastTimer=setTimeout(()=>t.className='toast',4800);
}
function changePage(page){
  if(!$('page-'+page))return;
  state.current=page;
  document.querySelectorAll('.page').forEach(el=>el.classList.toggle('shown',el.id==='page-'+page));
  nav.forEach(btn=>btn.classList.toggle('current',btn.dataset.page===page));
  document.querySelectorAll('[data-goto]').forEach(()=>{});
  window.scrollTo({top:0,behavior:'instant'});
}
async function api(path,body){
  const res=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  let json;
  try{json=await res.json()}catch{throw new Error('Server tidak merespons dengan data JSON. Jalankan ulang app.py.')}
  if(!res.ok||!json.ok)throw new Error(json.error||'Proses gagal.');return json;
}
function bytesB64(bytes){
  let binary='';const chunk=32768;
  for(let i=0;i<bytes.length;i+=chunk)binary+=String.fromCharCode(...bytes.subarray(i,i+chunk));
  return btoa(binary);
}
function b64Bytes(b64){let binary=atob(b64),out=new Uint8Array(binary.length);for(let i=0;i<out.length;i++)out[i]=binary.charCodeAt(i);return out}
function readFile(input,onread){const file=input.files?.[0];if(!file)return;const reader=new FileReader();reader.onload=()=>onread(new Uint8Array(reader.result),file.name);reader.onerror=()=>showToast('File tidak dapat dibaca.',true);reader.readAsArrayBuffer(file)}
function download(bytes,filename,mime='application/octet-stream'){
  const blob=new Blob([bytes],{type:mime});const href=URL.createObjectURL(blob);const link=document.createElement('a');
  link.href=href;link.download=filename;document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(href),5000);
}
function statusText(n){return `${n.toLocaleString('id-ID')} byte`}
function trim(s,n=1600){return s.length>n?s.slice(0,n)+'\n… [pratinjau dipotong, seluruh file tetap diproses]':s}
function escapeHTML(text){return String(text).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function setBusy(btn,asyncJob){if(btn.disabled)return;const old=btn.textContent;btn.disabled=true;btn.textContent='Memproses…';return Promise.resolve().then(asyncJob).catch(e=>showToast(e.message||String(e),true)).finally(()=>{btn.disabled=false;btn.textContent=old})}
function configNode(context){
  const el=$('cfg-'+context);const isCompare=context==='compare',isFeistel=context==='feistel';
  let list= isCompare||isFeistel?['DES','3DES']:enumAlg;
  const label = (name,items)=>`<div class="field"><label>${name}</label><select id="${context}-${name==='ALGORITMA'?'algorithm':name==='MODE OPERASI'?'mode':'engine'}">${items.map(x=>`<option value="${x[0]}">${x[1]}</option>`).join('')}</select></div>`;
  el.innerHTML=label('ALGORITMA',list.map(v=>[v,v]))+
    (!isFeistel?label('MODE OPERASI',modes.map(v=>[v,v])):'')+
    (!isCompare&&!isFeistel?label('IMPLEMENTASI',[['own','Feistel Sendiri'],['library','Library Crypto']]):'')+
    `<div class="field"><label>KUNCI · PASSWORD / HEX</label><input spellcheck="false" id="${context}-key" autocomplete="off" placeholder="Ketik password sendiri atau HEX" value=""><div class="keytools"><button class="btn alt sm" data-key-action="example" data-context="${context}">Contoh</button><button class="btn alt sm" data-key-action="random" data-context="${context}">Acak</button></div><small class="hint" id="${context}-hint"></small></div>`+
    (!isCompare&&!isFeistel?`<div class="field"><label>IV / NONCE (opsional · HEX)</label><input spellcheck="false" id="${context}-iv" autocomplete="off" placeholder="Kosong = acak"><small class="hint">CBC: IV tersimpan pada ciphertext. GCM: nonce + tag disertakan.</small></div>`:'');
  $(context+'-algorithm').addEventListener('change',()=>refresh(context,true));
  if(!isFeistel)$(context+'-mode').addEventListener('change',()=>refresh(context,false));
  if(!isCompare&&!isFeistel)$(context+'-engine').addEventListener('change',()=>refresh(context,false));
  refresh(context,true);
}
function refresh(context,keyReset){
  const alg=$(context+'-algorithm').value;
  if(keyReset||!$(context+'-key').value)$(context+'-key').value=state.config.keys[alg];
  $(context+'-hint').textContent=alg==='DES'
    ? 'Masukkan password pilihan sendiri atau kunci HEX sepanjang 16 digit.'
    : alg==='3DES'
    ? 'Password 3DES minimal 13 karakter atau kunci HEX 48 digit.'
    : `Password teks bebas atau ${state.config.keys[alg].length} digit HEX. Simpan password untuk dekripsi.`;
  if(context==='compare'||context==='feistel')return;
  const engine=$(context+'-engine');const mode=$(context+'-mode');
  if(alg.startsWith('AES')){engine.value='library';engine.querySelector('option[value="own"]').disabled=true}
  else{engine.querySelector('option[value="own"]').disabled=false;if(mode.value==='GCM')mode.value='CBC'}
  mode.querySelector('option[value="GCM"]').disabled=!alg.startsWith('AES');
  choice[context]={algorithm:alg,mode:mode.value,engine:engine.value};
}
function getParams(context){
  const alg=$(context+'-algorithm').value;
  return {algorithm:alg,key:$(context+'-key').value.trim(),
    mode:(context==='feistel'?'ECB':$(context+'-mode').value),
    engine:(context==='compare'||context==='feistel'?'own':$(context+'-engine').value),
    iv:$(context+'-iv')?.value.trim()||''};
}
function selectAction(id){$('text-encrypt').classList.toggle('selected',id==='encrypt');$('text-decrypt').classList.toggle('selected',id==='decrypt')}
function setTextInput(txt){$('text-input').value=txt;state.textLast=null;updateTextInput()}
function updateTextInput(){const txt=$('text-input').value;$('text-input-meta').textContent=`${txt.length.toLocaleString('id-ID')} karakter • ${statusText(enc.encode(txt).length)}`}
async function operateText(action){
  const button=$(action==='encrypt'?'text-encrypt':'text-decrypt');return setBusy(button,async()=>{
   let txt=$('text-input').value;const p=getParams('text');
   if(action==='decrypt'&&state.textLast&&state.textLast.action==='encrypt'){
     txt=state.textLast.result;
   }
   const output=await api('/api/process',{...p,action,text:txt,export_format:$('text-export-format').value,input_format:$('text-input-format').value});
   $('text-output').value=output.result;
   $('text-output-meta').textContent=`${statusText(output.output_size)} • ${output.duration_ms} ms`;
   $('text-status').textContent=`${action==='encrypt'?'Enkripsi':'Dekripsi'} ${output.algorithm} / ${output.mode} berhasil • ${statusText(output.output_size)} • ${output.format}` + (action==='decrypt' && output.confidence ? ` • ${output.confidence}` : '');
   state.textLast={...output,action};if(action==='decrypt'){if(output.algorithm!==p.algorithm){$('text-algorithm').value=output.algorithm;refresh('text',false)}$('text-mode').value=output.mode;}selectAction(action);showToast(action==='decrypt' ? `Dekripsi berhasil: ${output.algorithm} / ${output.mode} (${output.confidence || 'format dikenali'}).` : 'Enkripsi berhasil.');
  });
}
function initText(){
  $('text-input').addEventListener('input',()=>{updateTextInput();if(state.textLast)state.textLast=null});
  $('text-example').addEventListener('click',()=>setTextInput('Pada mulanya Allah menciptakan langit dan bumi.\nContoh: baris pertama — tanda baca!?'));
  $('text-file').addEventListener('change',ev=>readFile(ev.target,(data,name)=>{setTextInput(decoder.decode(data));state.textLoaded=true;$('text-status').textContent=`Dimuat ${name}: ${statusText(data.length)}`;}));
  $('text-save-input').addEventListener('click',()=>download(enc.encode($('text-input').value),'plaintext.txt','text/plain;charset=utf-8'));
  $('text-encrypt').addEventListener('click',()=>operateText('encrypt'));
  $('text-decrypt').addEventListener('click',()=>operateText('decrypt'));
  $('text-copy').addEventListener('click',async()=>{try{await navigator.clipboard.writeText($('text-output').value);showToast('Hasil disalin.')}catch{showToast('Salin manual menggunakan Ctrl+C.',true)}});
  $('text-save-output').addEventListener('click',()=>{const raw=state.textLast?.result||$('text-output').value;download(enc.encode(raw),state.textLast?.name||'hasil.txt','text/plain;charset=utf-8')});
  $('text-move').addEventListener('click',()=>setTextInput($('text-output').value));
  $('text-clear').addEventListener('click',()=>{$('text-input').value='';$('text-output').value='';$('text-output-meta').textContent='Belum ada hasil';$('text-status').textContent='Siap mengolah teks';state.textLast=null;selectAction(null);updateTextInput()});
}
function setEncryptedFile(data,name){state.encryptFile={data,name};$('encrypt-to-decrypt').disabled=true;$('encrypt-file-info').textContent=`${name} • ${statusText(data.length)}`;$('encrypt-preview').textContent=trim(decoder.decode(data));state.encryptResult=null;$('encrypt-report').textContent='File siap dienkripsi.';$('encrypt-download').disabled=true;$('encrypt-recovered').disabled=true}
function setDecryptedFile(data,name){state.decryptFile={data,name};$('decrypt-input-format').value='AUTO';$('decrypt-file-info').textContent=`${name} • ${statusText(data.length)}`;$('decrypt-preview').textContent=trim(decoder.decode(data).slice(0,3000));state.decryptResult=null;$('decrypt-report').textContent='Ciphertext siap didekripsi.';$('decrypt-download').disabled=true;$('decrypt-convert').disabled=false}
function useSample(num,target){fetch('/api/sample/'+num).then(r=>r.json()).then(json=>{
 const bytes=b64Bytes(json.base64);if(target==='encrypt')setEncryptedFile(bytes,json.name);
 else if(target==='compare'){state.compareFile=bytes;$('compare-text').value=trim(json.text,12000);showToast('File '+json.name+' dimuat untuk perbandingan.');}
 else if(target==='feistel'){state.feistelFile=bytes;$('feistel-text').value=trim(json.text,12000);$('feistel-file-note').textContent=`${json.name}, ${statusText(bytes.length)}. Semua byte dipakai.`;$('feistel-type').value='text';}
 }).catch(err=>showToast(err.message,true))}
function initFiles(){
  $('encrypt-upload').addEventListener('change',ev=>readFile(ev.target,setEncryptedFile));
  $('decrypt-upload').addEventListener('change',ev=>readFile(ev.target,setDecryptedFile));
  $('decrypt-original').addEventListener('change',ev=>readFile(ev.target,(data,name)=>{state.decryptOriginal=data;$('decrypt-original-info').textContent=`File asli: ${name} • ${statusText(data.length)}`}));
  $('decrypt-friend').addEventListener('click',async()=>{
    try{
      const response=await fetch('/api/sample/cipher');const example=await response.json();
      setDecryptedFile(b64Bytes(example.base64),example.name);
      $('decrypt-file-algorithm').value='DES';refresh('decrypt-file',true);
      $('decrypt-file-mode').value='CBC';$('decrypt-file-engine').value='own';
      $('decrypt-file-key').value=example.example_key;
      showToast('Contoh ciphertext ZAR1 dimuat. Klik Dekripsi Dokumen.');
    }catch(e){showToast('Gagal memuat contoh: '+e.message,true)}
  });
  $('file-encrypt').addEventListener('click',()=>setBusy($('file-encrypt'),async()=>{
    if(!state.encryptFile)throw new Error('Pilih dokumen .txt terlebih dahulu.');
    state.encryptConfig=getParams('encrypt-file');const res=await api('/api/file',{...state.encryptConfig,action:'encrypt',export_format:$('encrypt-export-format').value,filename:state.encryptFile.name,
      file_data:bytesB64(state.encryptFile.data),verify:$('encrypt-verify').checked});
    state.encryptResult=res;$('encrypt-download').disabled=false;$('encrypt-recovered').disabled=!res.recovered_data;$('encrypt-to-decrypt').disabled=false;
    $('encrypt-report').textContent=`BERHASIL ✓\n\nAlgoritma: ${res.algorithm} / ${res.mode}\nDari: ${statusText(res.size_in)}\nCiphertext: ${statusText(res.size_out)}\nWaktu: ${res.duration_ms} ms`+
      (res.identical!==null?`\n\nPemulihan: ${res.identical?'IDENTIK ✓':'TIDAK IDENTIK ✗'}\nSHA-256: ${res.sha256}`:'');
    showToast('Enkripsi '+res.format+' berhasil. File TXT siap diunduh.');
  }));
  $('encrypt-download').addEventListener('click',()=>{const r=state.encryptResult;if(r)download(b64Bytes(r.output),r.name,'text/plain;charset=utf-8')});
  $('encrypt-recovered').addEventListener('click',()=>{const r=state.encryptResult;if(r?.recovered_data)download(b64Bytes(r.recovered_data),r.recovered_name,'text/plain;charset=utf-8')});
  $('encrypt-to-decrypt').addEventListener('click',()=>{
    if(!state.encryptResult||!state.encryptConfig)return;
    const r=state.encryptResult, p=state.encryptConfig;
    setDecryptedFile(b64Bytes(r.output),r.name);
    $('decrypt-file-algorithm').value=p.algorithm;refresh('decrypt-file',false);
    $('decrypt-file-mode').value=p.mode;$('decrypt-file-engine').value=p.engine;
    $('decrypt-file-key').value=p.key;
    $('decrypt-input-format').value='AUTO';state.decryptOriginal=state.encryptFile.data;
    $('decrypt-original-info').textContent='File asli dari proses enkripsi tersedia untuk verifikasi.';
    changePage('decrypt-file');showToast('File dan pengaturan diteruskan. Klik Dekripsi Dokumen.');
  });
  $('file-decrypt').addEventListener('click',()=>setBusy($('file-decrypt'),async()=>{
    if(!state.decryptFile)throw new Error('Pilih ciphertext .txt (HEX/ZAR1) atau .enc terlebih dahulu.');
    const res=await api('/api/file',{...getParams('decrypt-file'),action:'decrypt',input_format:$('decrypt-input-format').value,filename:state.decryptFile.name,
      file_data:bytesB64(state.decryptFile.data),original_data:state.decryptOriginal?bytesB64(state.decryptOriginal):null});
    state.decryptResult=res;$('decrypt-download').disabled=false;if($('decrypt-file-algorithm').value!==res.algorithm){$('decrypt-file-algorithm').value=res.algorithm;refresh('decrypt-file',false)}$('decrypt-file-mode').value=res.mode;
    $('decrypt-report').textContent=`BERHASIL ✓\n\nFormat: ${res.format}\nAlgoritma terdeteksi: ${res.algorithm} / ${res.mode}\n${res.confidence ? 'Validasi: '+res.confidence+'\n' : ''}Ciphertext: ${statusText(res.size_in)}\nPlaintext: ${statusText(res.size_out)}\nWaktu: ${res.duration_ms} ms`+
      (res.identical===null?'\n\nVerifikasi: file asli belum dipilih':`\n\nVerifikasi: ${res.identical?'IDENTIK ✓':'TIDAK IDENTIK ✗'}`)+`\nSHA-256:\n${res.sha256}`;
    $('decrypt-preview').textContent=trim(res.preview,2500);showToast(`Dekripsi berhasil: ${res.algorithm} / ${res.mode}. Unduh plaintext.`);
  }));
  $('decrypt-download').addEventListener('click',()=>{const r=state.decryptResult;if(r)download(b64Bytes(r.output),r.name,'text/plain;charset=utf-8')});
  $('decrypt-convert').addEventListener('click',()=>setBusy($('decrypt-convert'),async()=>{
    if(!state.decryptFile)throw new Error('Pilih file terenkripsi terlebih dahulu.');
    const res=await api('/api/convert',{...getParams('decrypt-file'),file_data:bytesB64(state.decryptFile.data),filename:state.decryptFile.name,export_format:$('decrypt-export-format').value});
    download(b64Bytes(res.output),res.name,'text/plain;charset=utf-8');
    showToast('Ciphertext disalin menjadi format '+res.export_format+'. Byte ciphertext tetap sama.');
  }));
}
function initCompare(){
  $('compare-text').addEventListener('input',()=>state.compareFile=null);
  $('compare-file').addEventListener('change',ev=>readFile(ev.target,(data,name)=>{state.compareFile=data;$('compare-text').value=trim(decoder.decode(data),14000);showToast(`${name} dimuat sepenuhnya untuk pengujian.`)}));
  $('compare-run').addEventListener('click',()=>setBusy($('compare-run'),async()=>{
    const result=await api('/api/compare',{...getParams('compare'),text:$('compare-text').value,file_data:state.compareFile?bytesB64(state.compareFile):null});
    $('compare-result').textContent=`${result.identical&&result.cross_decryption?'LULUS ✓':'GAGAL ✗'}\n\nAlgoritma: ${result.algorithm} / ${result.mode}\nPlaintext: ${statusText(result.input_size)}\nPadding: ${statusText(result.padded_size)}\nCiphertext: ${statusText(result.output_size)}\nCipher sama: ${result.identical}\nDekripsi silang dan byte-for-byte: ${result.cross_decryption}\n\n${result.derived_key?'Kunci: password teks → kunci uji turunan yang sama.\n\n':''}Feistel sendiri: ${result.own_ms} ms\nLibrary Crypto: ${result.library_ms} ms\n\nCiphertext HEX (awal): ${result.ciphertext_head}…`;
    showToast(result.identical?'Hasil sama dengan library.':'Hasil tidak identik.',!result.identical);
  }));
  $('compare-auto').addEventListener('click',()=>{changePage('tests');$('tests-run').click()});
}
function initTests(){
  $('tests-run').addEventListener('click',()=>setBusy($('tests-run'),async()=>{
    const r=await api('/api/tests',{});
    $('tests-result').innerHTML=`<b class="good">${r.passed} lulus</b> · <b class="bad">${r.failed} gagal</b> · ${r.skipped} dilewati`+
      `<div class="table-scroll" style="margin-top:13px"><table><thead><tr><th>Pengujian</th><th>Status</th><th>Keterangan</th></tr></thead><tbody>`+
      r.cases.map(c=>`<tr><td>${escapeHTML(c.name)}</td><td class="${c.ok===true?'good':c.ok===false?'bad':''}">${c.ok===true?'LULUS':c.ok===false?'GAGAL':'DILEWATI'}</td><td>${escapeHTML(c.detail)}</td></tr>`).join('')+`</tbody></table></div>`;
  }));
}
function initFeistel(){
  $('feistel-standard').addEventListener('click',()=>{$('feistel-algorithm').value='DES';refresh('feistel',true);$('feistel-type').value='hex';$('feistel-index').value='1';$('feistel-text').value='0123456789ABCDEF';state.feistelFile=null;$('feistel-file-note').textContent='Vektor uji standar DES.'});
  $('feistel-text').addEventListener('input',()=>{state.feistelFile=null;$('feistel-file-note').textContent='Input manual.'});
  $('feistel-file').addEventListener('change',ev=>readFile(ev.target,(data,name)=>{state.feistelFile=data;$('feistel-text').value=trim(decoder.decode(data),13000);$('feistel-file-note').textContent=`${name} (${statusText(data.length)}), semua byte dianalisis.`;$('feistel-type').value='text'}));
  $('feistel-run').addEventListener('click',()=>setBusy($('feistel-run'),async()=>{
    const r=await api('/api/feistel',{...getParams('feistel'),text:$('feistel-text').value,raw_hex:$('feistel-type').value==='hex'&&!state.feistelFile,
      index:$('feistel-index').value,file_data:state.feistelFile?bytesB64(state.feistelFile):null});
    $('feistel-result').innerHTML=`<b class="good">HASIL ${escapeHTML(r.algorithm)} — LULUS ✓</b><p>Blok ${r.block_index} dari ${r.total_blocks} • Input total ${statusText(r.total_bytes)}<br>Plaintext blok: <code>${r.block_hex}</code><br>Ciphertext: <code>${r.ciphertext}</code>${r.derived_key?'<br><small>Ronde memakai kunci turunan khusus analisis; ciphertext penuh memakai salt tersimpan yang berbeda.</small>':''}</p>`+
      r.traces.map(s=>`<div class="trace-stage"><h3>${escapeHTML(s.title)}</h3><div class="subhint">${s.input} → ${s.output}</div><div class="table-scroll"><table><thead><tr><th>Ronde</th><th>Subkunci</th><th>L</th><th>R</th><th>F(R,K)</th><th>Pembuktian XOR</th></tr></thead><tbody>`+
        s.rows.map(x=>`<tr><td>${x.round}</td><td>${x.subkey}</td><td>${x.l}</td><td>${x.r}</td><td>${x.f}</td><td>${escapeHTML(x.xor)}</td></tr>`).join('')+`</tbody></table></div></div>`).join('')+
      `<p>Rumus: Lᵢ = Rᵢ₋₁; Rᵢ = Lᵢ₋₁ ⊕ F(Rᵢ₋₁,Kᵢ). F = ekspansi E → XOR subkunci → S-box → permutasi P.</p>`;
    showToast('Perhitungan ronde Feistel selesai.');
  }));
}
function initGeneral(){
  nav.forEach(btn=>btn.addEventListener('click',()=>changePage(btn.dataset.page)));
  document.querySelectorAll('[data-goto]').forEach(btn=>btn.addEventListener('click',()=>changePage(btn.dataset.goto)));
  document.querySelectorAll('[data-example]').forEach(btn=>btn.addEventListener('click',()=>useSample(btn.dataset.example,btn.dataset.target)));
  document.querySelectorAll('[data-key-action]').forEach(btn=>btn.addEventListener('click',()=>{
    const c=btn.dataset.context,alg=$(c+'-algorithm').value;
    if(btn.dataset.keyAction==='example')$(c+'-key').value=state.config.keys[alg];
    else{const bytes=new Uint8Array(state.config.keys[alg].length/2);crypto.getRandomValues(bytes);
      // Hindari kunci 3DES yang berdegenerasi.
      $(c+'-key').value=Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('').toUpperCase()}
  }));
}
async function start(){
 try{const r=await fetch('/api/config');state.config=await r.json();ctx.forEach(configNode);initGeneral();initText();initFiles();initCompare();initTests();initFeistel();$('compare-text').value='Contoh: baris pertama — Pada mulanya Allah menciptakan langit dan bumi.\nBaris baru.'}
 catch(err){showToast('Gagal memuat konfigurasi server: '+err.message,true)}
}
start();
})();
