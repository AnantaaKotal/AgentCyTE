/* Core Topology Graph Logic (extracted from core_details.html)
 * Features:
 * - Force layout (grid mode removed)
 * - Optional clustering by type
 * - Mini-map viewport tracking
 * - Export (SVG / PNG)
 * - Delayed tooltip (500ms)
 * - Rectangle nodes sized by services count
 * - Persisted positions and pinning
 * - Manual zoom reset (Fit removed)
 * - Label wrapping, multi-line service count indicator
 */
(function(window, document, d3){
  function initCoreGraph(options){
    const {
      containerSelector = '#topologyGraph',
      nodes = [],
      linksRaw = [],
      xmlPath = '_default'
    } = options || {};
    const container = document.querySelector(containerSelector);
    if(!container || !nodes.length){ return; }

    // Build links index mapping id/name -> index
    const idIndex = new Map();
    nodes.forEach((n,i)=>{ idIndex.set(String(n.id), i); idIndex.set(String(n.name), i); });
    const links = [];
    linksRaw.forEach(l => {
      const s = idIndex.get(String(l.node1)) ?? idIndex.get(String(l.node1_name));
      const t = idIndex.get(String(l.node2)) ?? idIndex.get(String(l.node2_name));
      if(s===undefined||t===undefined||s===t) return; links.push({ source:s, target:t });
    });

    // Restore positions
    const storageKey = 'coretg_graph_positions_' + xmlPath;
    let restoredPositions = {}; try { restoredPositions = JSON.parse(localStorage.getItem(storageKey)||'{}'); } catch(e){}
    nodes.forEach(n => { const saved = restoredPositions[n.id]; if(saved){ n.x=saved.x; n.y=saved.y; if(saved.pinned){ n.fx=saved.x; n.fy=saved.y; } } });

    const width = container.clientWidth; const height = container.clientHeight;
    const svg = d3.select(container).append('svg')
      .attr('width', width)
      .attr('height', height)
      .style('cursor','grab')
      .on('mousedown', ()=> svg.style('cursor','grabbing'))
      .on('mouseup mouseleave', ()=> svg.style('cursor','grab'));

    const g = svg.append('g');
    const zoomBehavior = d3.zoom().scaleExtent([0.15,6]).on('zoom', ev=> { g.attr('transform', ev.transform); updateMiniMapViewport(ev.transform); });
    svg.call(zoomBehavior);

    const vulnerabilityColor = '#28a745';
    const typeColor = d3.scaleOrdinal()
      .domain(['router','switch','hub','wlan','host','pc','server','docker'])
      .range(['#d9534f','#f0ad4e','#5bc0de','#5cb85c','#0275d8','#6610f2','#6f42c1','#9c27b0']);

    const linkCounts = new Array(nodes.length).fill(0); links.forEach(l => { linkCounts[l.source]++; linkCounts[l.target]++; });

    let clusterMode = 'off';

    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id((d,i)=> i).distance(160).strength(0.35))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(width/2, height/2))
      .force('collision', d3.forceCollide().radius(d => {
        const svc = (d.services||[]).length;
        const w = 70 + Math.min(100, svc * 8);
        const h = 36 + Math.min(24, svc * 1.2);
        return Math.max(w,h)/2 + 14;
      }));

    const link = g.selectAll('line.link')
      .data(links)
      .enter().append('line')
      .attr('class','link')
      .attr('stroke','#999')
      .attr('stroke-opacity',0.6)
      .attr('stroke-width',1.4);

    const nodeGroup = g.selectAll('g.node')
      .data(nodes)
      .enter().append('g')
      .attr('class', d => 'node' + ((d.type||'').toLowerCase()==='switch' ? ' switch-node' : ''))
      .style('cursor','pointer')
      .call(d3.drag()
        .on('start', (ev,d)=>{ if(!ev.active) simulation.alphaTarget(0.35).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', (ev,d)=>{ d.fx = ev.x; d.fy = ev.y; })
        .on('end', (ev)=>{ if(!ev.active) simulation.alphaTarget(0); })
      );

  const rects = nodeGroup.append('rect')
      .attr('width', d => 70 + Math.min(100, (d.services||[]).length * 8))
      .attr('height', d => 36 + Math.min(24, (d.services||[]).length * 1.2))
      .attr('x', d => -(70 + Math.min(100, (d.services||[]).length * 8)) / 2)
      .attr('y', d => -(36 + Math.min(24, (d.services||[]).length * 1.2)) / 2)
      .attr('rx',6).attr('ry',6)
      .attr('fill', d => {
        const t = (d.type||'').toLowerCase();
        const vulnList = Array.isArray(d.vulnerabilities) ? d.vulnerabilities
          : (d.metadata && Array.isArray(d.metadata.vulnerabilities) ? d.metadata.vulnerabilities : []);
        const hasVuln = (Array.isArray(vulnList) && vulnList.length > 0) || !!d.hasVuln;
        if(hasVuln && (t === 'host' || t === 'pc' || t === 'server')){
          return vulnerabilityColor;
        }
        return typeColor(t);
      })
      .attr('stroke','#222')
      .attr('stroke-width',1.2)
      .on('click', (ev,d)=>{
        // Pin/unpin in force layout
        if(currentLayout==='force') {
          const pinned = d.fx != null || d.fy != null;
          if(pinned){ d.fx=null; d.fy=null; } else { d.fx=d.x; d.fy=d.y; }
          d3.select(ev.currentTarget).attr('stroke-dasharray', pinned? null : '4,3');
        }
        // Expand accordion section for this node if present
        try {
          const accItem = document.querySelector(`.accordion-item[data-node-id="${CSS.escape(String(d.id))}"]`);
          if(accItem){
            const collapse = accItem.querySelector('.accordion-collapse');
            if(collapse && !collapse.classList.contains('show')) {
              new bootstrap.Collapse(collapse, {toggle: true});
            }
            accItem.scrollIntoView({behavior:'smooth', block:'start'});
            // Flash highlight class
            accItem.classList.remove('flash-highlight'); // restart animation if re-clicked
            // Force reflow to allow animation restart
            void accItem.offsetWidth;
            accItem.classList.add('flash-highlight');
            setTimeout(()=> accItem.classList.remove('flash-highlight'), 2000);
          }
        } catch(e){}
      })
      .on('mouseover', (ev,d)=> highlightNeighbors(d,true))
      .on('mouseout', (ev,d)=> highlightNeighbors(d,false));

    // Tooltip
    const tooltipEl = document.getElementById('graphTooltip');
    let tooltipTimer = null;
    function showTooltip(d, x, y){
      if(!tooltipEl) return;
      const svcList = (d.services||[]);
      const ifaceList = Array.isArray(d.interfaces) ? d.interfaces : [];
      const lines = [];
      lines.push(`<strong>${(d.name||'')} (${d.id})</strong>`);
      if(svcList.length){
        svcList.forEach(s => lines.push(s));
      } else {
        lines.push('<em>No Services</em>');
      }
      if(ifaceList.length){
        lines.push('<span class="text-muted">Interfaces</span>');
        ifaceList.slice(0, 4).forEach(iface => {
          const parts = [];
          if(iface.name){ parts.push(iface.name); }
          if(iface.mac){ parts.push(iface.mac); }
          const addrParts = [];
          if(iface.ipv4){ addrParts.push(`${iface.ipv4}${iface.ipv4_mask ? '/' + iface.ipv4_mask : ''}`); }
          if(iface.ipv6){ addrParts.push(`${iface.ipv6}${iface.ipv6_mask ? '/' + iface.ipv6_mask : ''}`); }
          if(addrParts.length){ parts.push(addrParts.join(' | ')); }
          if(parts.length){ lines.push(parts.join(' • ')); }
        });
        if(ifaceList.length > 4){
          lines.push(`(+${ifaceList.length - 4} more)`);
        }
      }
      tooltipEl.innerHTML = lines.join('<br>');
      tooltipEl.classList.remove('hidden');
      positionTooltip(x,y);
    }
    function hideTooltip(){ if(!tooltipEl) return; tooltipEl.classList.add('hidden'); }
    function positionTooltip(px,py){ if(!tooltipEl) return; const offX = px + 14; const offY = py + 14; tooltipEl.style.left = offX + 'px'; tooltipEl.style.top = offY + 'px'; }

    rects.on('mouseover.tooltip', (ev,d)=>{ if(tooltipTimer) clearTimeout(tooltipTimer); const [mx,my] = d3.pointer(ev, container); tooltipTimer = setTimeout(()=> showTooltip(d,mx,my), 500); })
      .on('mousemove.tooltip', (ev,d)=>{ if(!tooltipEl || tooltipEl.classList.contains('hidden')) return; const [mx,my]=d3.pointer(ev, container); positionTooltip(mx,my); })
      .on('mouseout.tooltip', ()=>{ if(tooltipTimer) { clearTimeout(tooltipTimer); tooltipTimer=null; } hideTooltip(); });

    // Labels (wrapped if needed)
    const MAX_LABEL_CHARS = 14;
    function wrapLabel(name){ if(!name) return ''; if(name.length <= MAX_LABEL_CHARS) return name; return name.slice(0, MAX_LABEL_CHARS-1) + '…'; }
    nodeGroup.append('text')
      .attr('text-anchor','middle')
      .attr('y',-2)
      .attr('font-size','10px')
      .attr('pointer-events','none')
      .attr('fill', d => ((d.type||'').toLowerCase()==='switch') ? '#000' : '#fff')
      .attr('class','label')
      .text(d => wrapLabel(d.name||''));

    nodeGroup.append('text')
      .attr('text-anchor','middle')
      .attr('y',12)
      .attr('font-size','8px')
      .attr('pointer-events','none')
      .attr('fill','#000')
      .text(d => (d.services||[]).length>0 ? (d.services||[]).length : '');

    function highlightNeighbors(d, on){
      const neighborSet = new Set();
      links.forEach(l => { if(l.source.index===d.index) neighborSet.add(l.target.index); if(l.target.index===d.index) neighborSet.add(l.source.index); });
      nodeGroup.classed('fade', n => on && n.index!==d.index && !neighborSet.has(n.index));
      link.classed('highlight', l => on && (l.source.index===d.index || l.target.index===d.index));
      if(!on){ nodeGroup.classed('fade', false); link.classed('highlight', false);} }

    // Legend builder (optional external container with id graphLegendItems)
    const legendEl = document.getElementById('graphLegendItems');
    if(legendEl){
      const degreePerType = new Map();
      links.forEach(l=>{ const inc=(idx)=>{ const t=(nodes[idx].type||'').toLowerCase(); if(!t) return; const s=degreePerType.get(t)||0; degreePerType.set(t,s+1); }; inc(l.source.index??l.source); inc(l.target.index??l.target); });
      const types = Array.from(new Set(nodes.map(n => (n.type||'').toLowerCase()))).filter(Boolean).sort();
      const hasVulnerableHosts = nodes.some(n => {
        const t = (n.type||'').toLowerCase();
        if(!(t === 'host' || t === 'pc' || t === 'server')) return false;
        const vulnList = Array.isArray(n.vulnerabilities) ? n.vulnerabilities
          : (n.metadata && Array.isArray(n.metadata.vulnerabilities) ? n.metadata.vulnerabilities : []);
        return (Array.isArray(vulnList) && vulnList.length > 0) || !!n.hasVuln;
      });
      let legendHtml = types.map(t => {
        const nodeCount = nodes.filter(n => (n.type||'').toLowerCase()===t).length;
        const deg = degreePerType.get(t)||0;
        const isSwitch = t === 'switch';
        const swatchStyle = isSwitch
          ? `display:inline-block;width:12px;height:12px;border:2px solid #ff9800;background:${typeColor(t)};box-shadow:0 0 0 1px #222 inset;`
          : `display:inline-block;width:12px;height:12px;border:1px solid #222;background:${typeColor(t)}`;
        return `<span class="d-flex align-items-center gap-1"><span style="${swatchStyle}"></span>${t}<span class="text-muted" style="font-size:.65rem;">(nodes:${nodeCount}, links:${deg})</span></span>`;
      }).join(' ');
      if(hasVulnerableHosts){
        const vulnSwatch = `<span class="d-flex align-items-center gap-1"><span style="display:inline-block;width:12px;height:12px;border:1px solid #222;background:${vulnerabilityColor}"></span>host (vulnerable)</span>`;
        legendHtml = legendHtml ? `${legendHtml} ${vulnSwatch}` : vulnSwatch;
      }
      legendEl.innerHTML = legendHtml;
    }

  simulation.on('tick', () => { updatePositions(); });

    function updatePositions(){
      link.attr('x1', d => d.source.x).attr('y1', d => d.source.y).attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      nodeGroup.attr('transform', d => `translate(${d.x},${d.y})`);
    }
    // (Grid layout removal: updateLinksStatic no longer needed)

    // Public controls hooking (if buttons exist)
    const resetBtn = document.getElementById('graphResetBtn');
    const clusterBtn = document.getElementById('graphClusterBtn');
    const exportSvgBtn = document.getElementById('graphExportSvgBtn');
    const exportPngBtn = document.getElementById('graphExportPngBtn');
    resetBtn?.addEventListener('click', () => { svg.transition().duration(400).call(zoomBehavior.transform, d3.zoomIdentity); nodes.forEach(n=>{ n.fx=null; n.fy=null; }); simulation.alpha(0.5).restart(); });

  clusterBtn?.addEventListener('click', () => { if(clusterMode==='off') { clusterMode='type'; clusterBtn.textContent='Cluster: Type'; applyClustering(); } else { clusterMode='off'; clusterBtn.textContent='Cluster: Off'; simulation.force('x', null).force('y', null); simulation.alpha(0.5).restart(); } });

    function applyClustering(){
      const types = Array.from(new Set(nodes.map(n => (n.type||'').toLowerCase()))).filter(Boolean);
      if(!types.length) return; const angleStep = (2*Math.PI)/types.length; const radius = Math.min(width,height)/3; const centers = new Map();
      types.forEach((t,i)=> centers.set(t,{x: Math.cos(i*angleStep)*radius, y: Math.sin(i*angleStep)*radius}));
      simulation.force('x', d3.forceX(d => (centers.get((d.type||'').toLowerCase())||{x:0}).x + width/2).strength(0.12));
      simulation.force('y', d3.forceY(d => (centers.get((d.type||'').toLowerCase())||{y:0}).y + height/2).strength(0.12));
  simulation.alpha(0.9).restart();
    }

    exportSvgBtn?.addEventListener('click', exportSvg);
    exportPngBtn?.addEventListener('click', exportPng);

    // centerAndFit removed (Fit button no longer present)

    function serializeSvg(){
      const clone = svg.node().cloneNode(true);
      clone.querySelectorAll('title').forEach(t => t.remove());
      const serializer = new XMLSerializer();
      let source = serializer.serializeToString(clone);
      if(!source.match(/^<svg[^>]+xmlns="http:\/\/www.w3.org\/2000\/svg"/)) source = source.replace('<svg','<svg xmlns="http://www.w3.org/2000/svg"');
      return source;
    }
    function exportSvg(){ const source = serializeSvg(); const blob = new Blob([source], {type:'image/svg+xml;charset=utf-8'}); const url = URL.createObjectURL(blob); triggerDownload(url, 'topology.svg'); setTimeout(()=> URL.revokeObjectURL(url), 1500); }
    function exportPng(){ const source = serializeSvg(); const img = new Image(); const svgBlob = new Blob([source], {type:'image/svg+xml;charset=utf-8'}); const url = URL.createObjectURL(svgBlob); img.onload = function(){ const canvas = document.createElement('canvas'); canvas.width = container.clientWidth * 2; canvas.height = container.clientHeight * 2; const ctx = canvas.getContext('2d'); ctx.fillStyle = '#ffffff'; ctx.fillRect(0,0,canvas.width,canvas.height); ctx.drawImage(img,0,0,canvas.width,canvas.height); URL.revokeObjectURL(url); canvas.toBlob(b => { const pngUrl = URL.createObjectURL(b); triggerDownload(pngUrl,'topology.png'); setTimeout(()=>URL.revokeObjectURL(pngUrl), 1500); }, 'image/png'); }; img.src = url; }
    function triggerDownload(url, filename){ const a = document.createElement('a'); a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove(); }

    // Mini-map
    const miniMap = document.getElementById('graphMiniMap');
    const miniSvg = miniMap ? d3.select(miniMap).select('svg'):null; let miniG, miniLinks, miniNodes, viewRect;
    if(miniSvg){ miniG = miniSvg.append('g'); miniLinks = miniG.selectAll('line').data(links).enter().append('line').attr('stroke','#bbb').attr('stroke-width',1); miniNodes = miniG.selectAll('circle').data(nodes).enter().append('circle').attr('r',2.8).attr('fill', d=>typeColor((d.type||'').toLowerCase())); viewRect = miniG.append('rect').attr('fill','none').attr('stroke','#ff5722').attr('stroke-width',1); miniMap.addEventListener('mousedown', (ev)=>{ ev.preventDefault(); const pt = d3.pointer(ev, miniG.node()); svg.transition().duration(300).call(zoomBehavior.transform, d3.zoomIdentity.translate(container.clientWidth/2 - pt[0], container.clientHeight/2 - pt[1]).scale(1)); }); }
    function updateMiniMap(){ if(!miniSvg) return; const xs=nodes.map(n=>n.x), ys=nodes.map(n=>n.y); if(!xs.length) return; const minX=Math.min(...xs), maxX=Math.max(...xs), minY=Math.min(...ys), maxY=Math.max(...ys); const pad=40; const w=(maxX-minX)||1, h=(maxY-minY)||1; const scaleX=(160-pad)/w, scaleY=(120-pad)/h; const s=Math.min(scaleX, scaleY); const ox=(160 - w*s)/2, oy=(120 - h*s)/2; miniG.attr('transform', `translate(${ox - minX*s},${oy - minY*s}) scale(${s})`); miniLinks.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y).attr('x2',d=>d.target.x).attr('y2',d=>d.target.y); miniNodes.attr('cx',d=>d.x).attr('cy',d=>d.y); updateMiniMapViewport(d3.zoomTransform(svg.node())); }
    function updateMiniMapViewport(z){ if(!viewRect) return; try { const t=z||d3.zoomTransform(svg.node()); const inv=t.invert([0,0]); const inv2=t.invert([container.clientWidth, container.clientHeight]); viewRect.attr('x',inv[0]).attr('y',inv[1]).attr('width',inv2[0]-inv[0]).attr('height',inv2[1]-inv[1]); } catch(e){} }
  simulation.on('tick.graphExtras', ()=> { updateMiniMap(); });
    setInterval(()=> updateMiniMap(), 1500); updateMiniMap();

    // Stats
    const statsEl = document.getElementById('graphStats'); if(statsEl){ statsEl.textContent = `${nodes.length} nodes, ${links.length} links`; }

    // Resize handling
  const ro = new ResizeObserver(entries => { for(const e of entries){ const w = e.contentRect.width; const h = e.contentRect.height; svg.attr('width', w).attr('height', h); simulation.force('center', d3.forceCenter(w/2, h/2)); simulation.alpha(0.15).restart(); } });
    ro.observe(container);

    // Persist positions on unload
    window.addEventListener('beforeunload', ()=> { try { const out={}; nodes.forEach(n=> out[n.id]={x:n.x,y:n.y,pinned:(n.fx!=null||n.fy!=null)}); localStorage.setItem(storageKey, JSON.stringify(out)); } catch(e){} });

    return { exportSvg, exportPng, applyClustering, simulation, nodes, links };
  }
  window.CoreGraph = { init: initCoreGraph };
})(window, document, d3);
