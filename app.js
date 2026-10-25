// Cockpit PEA — app téléphone (lecture seule).
// Télécharge donnees.json (copie CHIFFRÉE publiée par le PC), la déchiffre avec le mot de passe (WebCrypto), l'affiche.
// Aucune saisie ici : les opérations se font toujours dans le Cockpit du PC.

const FICHIER = 'donnees.json';
const DONNEES_ASSOCIEES = new TextEncoder().encode('cockpit-pea-v1'); // identiques au PC (services/mobile.py)
const CLE_ENVELOPPE = 'cockpit-enveloppe'; // dernière copie chiffrée (lecture hors connexion)
const CLE_SECRET = 'cockpit-cle';          // clé déchiffrante mémorisée (si « se souvenir »)
const CLE_THEME = 'cockpit-theme';
const VIEILLE_H = 3;                       // au-delà : la copie est signalée comme ancienne

const etat = { enveloppe: null, cle: null, d: null, masque: false, chargement: false, erreur: null, derniereLecture: 0, filtreActus: 'tout' };
const $ = (s, r = document) => r.querySelector(s);

// ---------------------------------------------------------------- stockage du téléphone (jamais bloquant)
const stock = {
  lire(k) { try { return localStorage.getItem(k); } catch { return null; } },
  ecrire(k, v) { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch { /* plein ou bloqué */ } },
};

// ---------------------------------------------------------------- mise en forme à la française
const fEuros = new Intl.NumberFormat('fr-FR', { style: 'currency', currency: 'EUR' });
const fNombre = new Intl.NumberFormat('fr-FR', { maximumFractionDigits: 2 });
const fPct = new Intl.NumberFormat('fr-FR', { minimumFractionDigits: 1, maximumFractionDigits: 1 });
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const euros = (n) => (n == null ? '—' : etat.masque ? '•••• €' : fEuros.format(n));
const eurosSigne = (n) => (n == null ? '—' : etat.masque ? '•••• €' : (n > 0 ? '+' : '') + fEuros.format(n));
const nombre = (n) => (n == null ? '—' : fNombre.format(n));
const pct = (n, signe = true) => (n == null ? '—' : (signe && n > 0 ? '+' : '') + fPct.format(n) + ' %');
const signe = (n) => (n == null || Math.abs(n) < 0.005 ? 'muet' : n > 0 ? 'pos' : 'neg');
const dateFr = (iso) => (iso ? iso.slice(0, 10).split('-').reverse().join('/') : '—');
const dateCourte = (iso) => (iso ? `${iso.slice(8, 10)}/${iso.slice(5, 7)}` : '—');
const heure = (iso) => (iso ? iso.slice(11, 16) : '');
const dateHeure = (iso) => (iso ? `${dateCourte(iso)} à ${heure(iso)}` : '—');
const JOURS = ['dim.', 'lun.', 'mar.', 'mer.', 'jeu.', 'ven.', 'sam.'];
const jourSemaine = (iso) => JOURS[new Date(iso.slice(0, 10) + 'T12:00:00').getDay()];

/** Âge (en heures) d'un horaire de Paris « AAAA-MM-JJTHH:MM:SS ». */
function ageHeures(iso) {
  if (!iso) return Infinity;
  const paris = new Date(new Date().toLocaleString('en-US', { timeZone: 'Europe/Paris' }));
  return (paris - new Date(iso)) / 3600000;
}

// ---------------------------------------------------------------- déchiffrement (inverse de services/mobile.py)
const octets = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const b64 = (tab) => btoa(String.fromCharCode(...tab));

async function deriverCle(motDePasse, env) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(motDePasse), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: octets(env.sel), iterations: env.tours }, base, 256);
  return new Uint8Array(bits);
}

async function dechiffrer(env, cleBrute) {
  const cle = await crypto.subtle.importKey('raw', cleBrute, 'AES-GCM', false, ['decrypt']);
  const clair = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: octets(env.iv), additionalData: DONNEES_ASSOCIEES }, cle, octets(env.donnees));
  const flux = new Blob([clair]).stream().pipeThrough(new DecompressionStream('gzip'));
  return JSON.parse(await new Response(flux).text());
}

function cleMemorisee(env) {
  try {
    const m = JSON.parse(stock.lire(CLE_SECRET) || 'null');
    return m && m.sel === env.sel ? octets(m.cle) : null; // nouveau mot de passe sur le PC = nouveau sel
  } catch { return null; }
}

// ---------------------------------------------------------------- chargement de la copie
async function telecharger() {
  const r = await fetch(`${FICHIER}?t=${Date.now()}`, { cache: 'no-store' });
  if (r.status === 404) throw new Error('aucune copie publiée pour l\'instant (choisis un mot de passe dans Paramètres → App téléphone, sur le PC)');
  if (!r.ok) throw new Error(`erreur ${r.status}`);
  return r.json();
}

async function ouvrir(env) {
  const cle = etat.cle && etat.enveloppe?.sel === env.sel ? etat.cle : cleMemorisee(env);
  if (!cle) { etat.enveloppe = env; etat.cle = null; etat.d = null; return; }
  try {
    etat.d = await dechiffrer(env, cle);
    etat.enveloppe = env;
    etat.cle = cle;
  } catch {
    etat.enveloppe = env; etat.cle = null; etat.d = null; // clé périmée : redemander le mot de passe
  }
}

async function actualiser(silencieux = false) {
  if (etat.chargement) return;
  etat.chargement = true;
  etat.erreur = null;
  if (!silencieux) majEntete();
  try {
    const env = await telecharger();
    etat.derniereLecture = Date.now();
    if (env.donnees !== etat.enveloppe?.donnees || !etat.d) {
      await ouvrir(env);
      if (etat.d) stock.ecrire(CLE_ENVELOPPE, JSON.stringify(env));
    }
  } catch (e) {
    etat.erreur = navigator.onLine === false ? 'Pas de réseau : dernière copie gardée dans le téléphone.' : `Copie non téléchargée : ${e.message}.`;
  } finally {
    etat.chargement = false;
    rendre();
  }
}

async function deverrouiller(motDePasse, seSouvenir) {
  const env = etat.enveloppe;
  const cle = await deriverCle(motDePasse, env);
  etat.d = await dechiffrer(env, cle); // lève une erreur si le mot de passe est faux
  etat.cle = cle;
  stock.ecrire(CLE_ENVELOPPE, JSON.stringify(env));
  stock.ecrire(CLE_SECRET, seSouvenir ? JSON.stringify({ sel: env.sel, cle: b64(cle) }) : null);
}

// ---------------------------------------------------------------- petits composants
const badge = (texte, couleur = 'gris') => `<span class="badge ${couleur}">${esc(texte)}</span>`;
const vide = (texte) => `<p class="vide">${texte}</p>`;
const lienFiche = (t) => `#/fiche/${encodeURIComponent(t)}`;
const points = (liste, classe, symbole) => (liste?.length ? `<ul class="points ${classe}">${liste.map((e) => `<li data-s="${symbole}">${esc(e)}</li>`).join('')}</ul>` : '');

/** Courbe SVG simple : séries de points [{x: ms, y}], couleurs CSS. */
function courbe(series, hauteur = 150) {
  const tous = series.flatMap((s) => s.points);
  if (tous.length < 2) return '';
  const L = 320, H = hauteur, mg = 4;
  const xs = tous.map((p) => p.x), ys = tous.map((p) => p.y);
  const x0 = Math.min(...xs), x1 = Math.max(...xs);
  let y0 = Math.min(...ys), y1 = Math.max(...ys);
  if (y1 - y0 < 1e-9) { y0 -= 1; y1 += 1; }
  const pad = (y1 - y0) * 0.08; y0 -= pad; y1 += pad;
  const X = (x) => mg + ((x - x0) / (x1 - x0 || 1)) * (L - 2 * mg);
  const Y = (y) => H - mg - ((y - y0) / (y1 - y0)) * (H - 2 * mg);
  const grille = [0.25, 0.5, 0.75].map((f) => `<line x1="0" x2="${L}" y1="${(H * f).toFixed(1)}" y2="${(H * f).toFixed(1)}" stroke="var(--grille)" stroke-width="1"/>`).join('');
  const lignes = series.map((s) => `<polyline fill="none" stroke="${s.couleur}" stroke-width="2" stroke-linejoin="round" ${s.pointille ? 'stroke-dasharray="5 4"' : ''} points="${s.points.map((p) => `${X(p.x).toFixed(1)},${Y(p.y).toFixed(1)}`).join(' ')}"/>`).join('');
  const legende = series.map((s) => `<span><i style="background:${s.couleur}"></i>${esc(s.nom)}</span>`).join('');
  return `<svg class="courbe" viewBox="0 0 ${L} ${H}" role="img" aria-label="Évolution">${grille}${lignes}</svg>
    <div class="legende">${legende}<span style="margin-left:auto">${etat.masque ? '' : `${euros(Math.min(...ys))} → ${euros(Math.max(...ys))}`}</span></div>`;
}

function barrePoche(p) {
  const couleur = Math.abs(p.ecart_pts) > 5 ? 'var(--orange)' : 'var(--serie-1)';
  return `<div style="margin:10px 0">
    <div class="entre petit"><span class="gras">${esc(p.nom)}</span><span class="chiffres">${euros(p.valeur)} · <span class="${signe(p.plus_value)}">${pct(p.plus_value_pct)}</span></span></div>
    <div class="barre" style="margin-top:5px"><i style="width:${Math.min(100, p.part_pct)}%;background:${couleur}"></i><b style="left:${p.cible_pct}%"></b></div>
    <div class="mini muet">${pct(p.part_pct, false)} du PEA · cible ${pct(p.cible_pct, false)}</div>
  </div>`;
}

const COULEUR_STATUT = { fait: 'vert', en_retard: 'rouge', bientot: 'orange', a_faire: 'gris' };
const COULEUR_NIVEAU = { critique: 'rouge', attention: 'orange', info: 'gris' };
const fondIndice = (n) => (n == null ? 'gris' : n >= 62 ? 'vert' : n >= 45 ? 'gris' : n >= 35 ? 'orange' : 'rouge');

// ---------------------------------------------------------------- pages
function pageAccueil(d) {
  const pf = d.portefeuille || {}, st = d.statut || {}, perf = d.performances || {};
  const marche = st.marche || {};
  const alertes = (d.alertes || []).filter((a) => !a.traitee);
  const taches = (d.taches || []).filter((t) => t.statut !== 'fait').sort((a, b) => (a.echeance || '').localeCompare(b.echeance || ''));
  const evo = (perf.evolution || []).filter((e) => e.valeur_totale > 0 || e.total_verse > 0);
  const debut = !pf.total_verse && !pf.valeur_totale;
  return `
    <p class="petit muet">${marche.ouvert ? '🟢' : '⚪'} ${esc(marche.message || '')}${st.derniere_maj_prix ? ` · prix du ${dateHeure(st.derniere_maj_prix)} (différés ~15 min)` : ''}</p>
    <div class="carte">
      <div class="muet petit">Valeur du PEA</div>
      <div class="grand chiffres">${euros(pf.valeur_totale)}</div>
      <div class="chiffres"><span class="${signe(pf.plus_value)}">${eurosSigne(pf.plus_value)} (${pct(pf.plus_value_pct)})</span> <span class="muet">depuis l'ouverture</span></div>
      <div class="chiffres petit"><span class="${signe(pf.variation_jour)}">${eurosSigne(pf.variation_jour)} (${pct(pf.variation_jour_pct)})</span> <span class="muet">aujourd'hui</span></div>
      ${pf.prix_anciens ? '<p class="mini att">⚠️ Certains prix sont anciens (dernière valeur connue).</p>' : ''}
      ${debut ? '<div class="message" style="margin:10px 0 0">Aucune opération saisie pour l\'instant. Les saisies se font dans le Cockpit du PC.</div>' : ''}
      <div class="grille2" style="margin-top:12px">
        <div class="tuile"><div class="libelle">Total versé</div><div class="valeur chiffres">${euros(pf.total_verse)}</div></div>
        <div class="tuile"><div class="libelle">Liquidités</div><div class="valeur chiffres">${euros(pf.liquidites)}</div></div>
        <div class="tuile"><div class="libelle">Rendement annuel (TRI)</div><div class="valeur chiffres">${perf.tri_fiable ? pct(perf.tri_annualise) : '<span class="muet petit">pas encore assez de recul</span>'}</div></div>
        <div class="tuile"><div class="libelle">Budget poche actions</div><div class="valeur chiffres">${euros(pf.budget_actions)}</div></div>
      </div>
    </div>
    <div class="carte"><h2>Mes poches</h2>${Object.values(pf.poches || {}).map(barrePoche).join('')}
      <p class="mini muet">Le trait vertical marque la cible ; orange = écart de plus de 5 points.</p></div>
    ${evo.length >= 2 ? `<div class="carte"><h2>Évolution</h2>${courbe([
      { nom: 'Valeur', couleur: 'var(--serie-1)', points: evo.map((e) => ({ x: Date.parse(e.date), y: e.valeur_totale })) },
      { nom: 'Versé', couleur: 'var(--serie-2)', pointille: true, points: evo.map((e) => ({ x: Date.parse(e.date), y: e.total_verse })) },
    ])}</div>` : ''}
    <div class="carte"><div class="entre"><h2>Alertes</h2><a href="#/alertes" class="petit">Tout voir</a></div>
      ${alertes.length ? `<ul class="liste">${alertes.slice(0, 3).map(ligneAlerte).join('')}</ul>` : '<p class="muet petit">Aucune alerte à traiter.</p>'}</div>
    <div class="carte"><div class="entre"><h2>À faire</h2><a href="#/taches" class="petit">Tout voir</a></div>
      <ul class="liste">${taches.slice(0, 3).map(ligneTache).join('') || '<li class="muet petit">Rien à faire.</li>'}</ul></div>
    <div class="carte"><h2>Repères du PEA</h2>
      <div class="entre petit"><span>Règle des 5 ans</span><span class="chiffres">${pf.jours_avant_5_ans > 0 ? `encore ${nombre(pf.jours_avant_5_ans)} jours (${dateFr(pf.date_5_ans)})` : '✓ atteinte'}</span></div>
      <div class="entre petit"><span>Plafond de versements restant</span><span class="chiffres">${euros(pf.plafond_restant)}</span></div>
      <div class="entre petit"><span>Frais payés</span><span class="chiffres">${euros(pf.frais_total)}</span></div>
    </div>`;
}

function lignePosition(p, analyses) {
  const contenu = `<div class="flex"><div class="nom">${esc(p.nom || p.ticker)}</div>
      <div class="mini muet chiffres">${nombre(p.quantite)} × ${nombre(p.prix_actuel)} € · PRU ${nombre(p.prix_moyen)} €</div></div>
    <div class="droite chiffres"><div class="gras">${euros(p.valeur)}</div>
      <div class="mini ${signe(p.plus_value)}">${eurosSigne(p.plus_value)} · ${pct(p.plus_value_pct)}</div></div>`;
  return `<li>${analyses[p.ticker] ? `<a class="element" href="${lienFiche(p.ticker)}">${contenu}</a>` : `<div class="element">${contenu}</div>`}</li>`;
}

function pageActions(d) {
  const pf = d.portefeuille || {}, ac = d.actions || {}, analyses = d.analyses || {};
  const positions = pf.positions || [];
  const NOMS = { etf_monde: 'ETF Monde', etf_emergents: 'ETF Émergents', actions: 'Poche actions' };
  const blocs = Object.keys(NOMS).map((poche) => {
    const lignes = positions.filter((p) => p.poche === poche);
    return lignes.length ? `<h3>${NOMS[poche]}</h3><ul class="liste">${lignes.map((p) => lignePosition(p, analyses)).join('')}</ul>` : '';
  }).join('');
  const watch = (ac.watchlist || []).map((w) => {
    const a = analyses[w.ticker];
    return `<li><a class="element" href="${lienFiche(w.ticker)}">
      <div class="indice ${a ? fondIndice(a.indice_achat_pct) : 'gris'}">${a ? a.indice_achat_pct : '—'}</div>
      <div class="flex"><div class="nom">${esc(w.nom || w.ticker)}</div>
        <div class="mini muet">${w.achetable ? `✓ achetable (${w.nb_achetables} titre${w.nb_achetables > 1 ? 's' : ''})` : `il manque ${euros(w.manque)}${w.mois_pour_y_arriver ? ` (≈ ${w.mois_pour_y_arriver} mois)` : ''}`}${w.sous_cible ? ' · sous ton prix cible' : ''}</div></div>
      <div class="droite chiffres"><div class="gras">${nombre(w.prix)} €</div><div class="mini ${signe(w.variation_jour_pct)}">${pct(w.variation_jour_pct)}</div></div></a></li>`;
  }).join('');
  return `<h1>Mes actions</h1>
    <div class="carte">${blocs || '<p class="muet">Aucune position pour l\'instant.</p>'}</div>
    <div class="carte"><div class="entre"><h2>Watchlist</h2><span class="petit muet">budget ${euros(ac.budget)}</span></div>
      <p class="mini muet">Le chiffre à gauche est l'indice d'achat (0 à 100 %).</p>
      ${watch ? `<ul class="liste">${watch}</ul>` : '<p class="muet petit">Watchlist vide.</p>'}</div>`;
}

/** Trouve une fiche d'analyse : mes actions / watchlist, Top 5, sinon le contexte d'une alerte. */
function trouverFiche(d, t) {
  return d.analyses?.[t] || (d.top?.top || []).find((x) => x.ticker === t)
    || (d.alertes || []).find((a) => a.ticker === t && a.contexte)?.contexte || null;
}

function contenuFiche(a) {
  const v = a.vente;
  const criteres = (a.criteres || []).map((c) => `<div class="critere"><span class="tronque">${esc(c.nom)}</span>
      <div class="barre">${c.score != null ? `<i style="width:${c.score}%;background:var(--${{ vert: 'vert', orange: 'orange', rouge: 'rouge', gris: 'muet' }[fondIndice(c.score)]})"></i>` : ''}</div>
      <span class="chiffres gras" style="text-align:right">${c.score ?? '—'}</span><small>${esc(c.explication || 'donnée manquante')} · poids ${c.poids} %</small></div>`).join('');
  return `
    <div class="carte"><div class="ligne">
      <div class="indice ${a.couleur || fondIndice(a.indice_achat_pct)}" style="width:64px;height:64px;font-size:20px">${a.indice_achat_pct ?? '—'}</div>
      <div class="flex"><div class="muet mini">Indice d'achat</div><div class="gras">${badge(a.verdict || '—', a.couleur)}</div>
        ${a.confiance_pct != null ? `<div class="mini muet">Données disponibles : ${a.confiance_pct} %</div>` : ''}</div></div>
      ${a.conseil ? `<p class="petit" style="margin-top:10px">${esc(a.conseil)}</p>` : ''}</div>
    ${v ? `<div class="carte"><div class="ligne"><div class="indice ${v.couleur}" style="width:64px;height:64px;font-size:20px">${v.indice_vente_pct}</div>
      <div class="flex"><div class="muet mini">Indice de vente — tu la détiens</div><div class="gras">${badge(v.verdict, v.couleur)}</div>
      <div class="mini muet chiffres">PRU ${nombre(v.prix_moyen)} € · ${pct(v.plus_value_pct)}${v.jours_detention != null ? ` · ${v.jours_detention} j` : ''}</div></div></div>
      ${points(v.raisons, 'info', '•')}</div>` : ''}
    ${a.avantages?.length || a.inconvenients?.length ? `<div class="carte"><h3 style="margin-top:0">Avantages</h3>${points(a.avantages, 'plus', '+') || '<p class="muet petit">—</p>'}
      <h3>Inconvénients</h3>${points(a.inconvenients, 'moins', '−') || '<p class="muet petit">—</p>'}</div>` : ''}
    ${criteres ? `<div class="carte"><h2>Les 10 critères</h2>${criteres}</div>` : ''}
    ${a.contexte?.length ? `<div class="carte"><h2>Remise en contexte</h2>${points(a.contexte, 'info', '•')}</div>` : ''}
    ${a.description ? `<div class="carte"><details><summary class="gras">L'entreprise</summary><p class="petit">${esc(a.description)}</p></details></div>` : ''}`;
}

function pageFiche(d, t) {
  const a = trouverFiche(d, t);
  if (!a) return `<h1>${esc(t)}</h1>${vide('Pas de fiche d\'analyse pour ce titre dans la copie.')}`;
  return `<p><a href="javascript:history.back()">‹ Retour</a></p>
    <h1 style="margin-bottom:2px">${esc(a.nom || t)}</h1>
    <p class="muet petit">${esc(t)}${a.secteur ? ` · ${esc(a.secteur)}` : ''}${a.pays ? ` · ${esc(a.pays)}` : ''}</p>
    ${a.prix != null ? `<p class="chiffres"><span class="gras">${nombre(a.prix)} €</span> <span class="mini muet">cours du ${dateHeure(a.prix_horodatage)}${a.differe ? ' (différé)' : ''}</span></p>` : ''}
    ${contenuFiche(a)}
    <p class="mini muet">Fiche calculée le ${dateHeure(a.calcule_le)}. Score transparent : 10 critères expliqués, aucune promesse de gain.</p>`;
}

function pageTop(d) {
  const top = d.top || {};
  const lignes = (top.top || []).map((a, i) => `<li><a class="element" href="${lienFiche(a.ticker)}">
      <div class="indice ${a.couleur}">${a.indice_achat_pct}</div>
      <div class="flex"><div class="nom">${i + 1}. ${esc(a.nom)}</div><div class="mini muet tronque">${esc(a.secteur || '')} · ${esc(a.pays || '')}</div></div>
      <div class="droite"><div class="gras chiffres">${nombre(a.prix)} €</div>${badge(a.verdict, a.couleur)}</div></a></li>`).join('');
  return `<h1>Top 5</h1>
    <p class="petit muet">Les 5 actions éligibles PEA les mieux notées par l'indice d'achat (max 2 par secteur), parmi ${nombre(top.nb_analysees)} analysées${top.dernier_scan ? `, le ${dateHeure(top.dernier_scan)}` : ''}.</p>
    <div class="carte">${lignes ? `<ul class="liste">${lignes}</ul>` : '<p class="muet">Classement pas encore calculé.</p>'}</div>
    <p class="mini muet">Ce sont des opportunités à examiner. Touche une action pour voir ses 10 critères.</p>`;
}

function pageRobots(d) {
  const robots = [...(d.robots?.robots || [])].sort((a, b) => (b.gain_pct ?? -1e9) - (a.gain_pct ?? -1e9));
  const lignes = robots.map((r) => `<li><a class="element" href="#/robot/${r.id}">
      <div class="indice" style="color:${esc(r.couleur)}">${esc(r.icone || '🤖')}</div>
      <div class="flex"><div class="nom">${esc(r.nom)}${r.reference ? ' ' + badge('référence') : ''}${r.actif ? '' : ' ' + badge('en pause')}</div>
        <div class="mini muet tronque">${esc(r.nom_strategie || '')} · ${r.nb_positions} ligne${r.nb_positions > 1 ? 's' : ''} · ${r.nb_trades} trade${r.nb_trades > 1 ? 's' : ''}</div></div>
      <div class="droite chiffres"><div class="gras">${euros(r.valeur)}</div><div class="mini ${signe(r.gain)}">${pct(r.gain_pct)}</div></div></a></li>`).join('');
  return `<h1>Robots</h1>
    <div class="message attention">🧪 SIMULATION — argent fictif. Aucun ordre réel.</div>
    <div class="carte">${lignes ? `<ul class="liste">${lignes}</ul>` : '<p class="muet">Aucun robot.</p>'}</div>
    <p class="mini muet">Classés par gain. Peu de recul au début : quelques jours ne disent rien d'une stratégie.</p>`;
}

function pageRobot(d, id) {
  const r = d.robots_detail?.[id];
  if (!r) return vide('Robot introuvable dans la copie.');
  const f = r.fiche || {};
  const evo = r.evolution || [];
  const positions = (r.positions || []).map((p) => `<li><div class="element"><div class="flex"><div class="nom">${esc(p.nom || p.ticker)}</div>
      <div class="mini muet chiffres">${nombre(p.quantite)} × ${nombre(p.prix_actuel)} € · PRU ${nombre(p.prix_moyen)} €${p.stop_loss ? ` · stop ${nombre(p.stop_loss)} €` : ''}</div></div>
      <div class="droite chiffres"><div class="gras">${euros(p.valeur)}</div><div class="mini ${signe(p.plus_value)}">${pct(p.plus_value_pct)}</div></div></div></li>`).join('');
  const trades = (r.trades || []).slice(0, 15).map((t) => `<li><div class="element"><div class="flex"><div class="nom">${esc(t.nom || t.ticker)}</div>
      <div class="mini muet">${dateCourte(t.date_achat)} → ${dateCourte(t.date_vente)} · ${nombre(t.quantite)} titres</div></div>
      <div class="droite chiffres"><div class="gras ${signe(t.resultat_net)}">${eurosSigne(t.resultat_net)}</div><div class="mini ${signe(t.rendement_pct)}">${pct(t.rendement_pct)}</div></div></div></li>`).join('');
  // journal : les décisions et trades, sans les messages techniques (rattrapage…)
  const journal = (r.journal || []).filter((j) => j.type !== 'info').slice(0, 12).map((j) => `<li class="petit" style="padding:8px 0"><span class="mini muet">${dateHeure(j.horodatage)}</span><br>${esc(j.message)}</li>`).join('');
  const regles = (titre, l) => (l?.length ? `<h3>${titre}</h3>${points(l, 'info', '•')}` : '');
  return `<p><a href="#/robots">‹ Robots</a></p>
    <h1 style="margin-bottom:2px">${esc(r.icone || '')} ${esc(r.nom)}</h1>
    <p class="muet petit">${esc(r.nom_strategie || '')} · 🧪 simulation, argent fictif</p>
    <div class="carte">
      <div class="grand chiffres">${euros(r.valeur)}</div>
      <div class="chiffres"><span class="${signe(r.gain)}">${eurosSigne(r.gain)} (${pct(r.gain_pct)})</span> <span class="muet">pour ${euros(r.verse)} versés</span></div>
      <div class="grille2" style="margin-top:12px">
        <div class="tuile"><div class="libelle">Liquidités</div><div class="valeur chiffres">${euros(r.liquidites)}</div></div>
        <div class="tuile"><div class="libelle">Pire baisse</div><div class="valeur chiffres neg">${pct(r.max_drawdown_pct)}</div></div>
        <div class="tuile"><div class="libelle">Trades gagnants</div><div class="valeur chiffres">${r.nb_trades ? pct(r.taux_reussite_pct, false) : '—'}</div></div>
        <div class="tuile"><div class="libelle">Frais payés</div><div class="valeur chiffres">${euros(r.frais_total)}</div></div>
      </div>
      ${evo.length >= 2 ? `<div style="margin-top:12px">${courbe([
        { nom: 'Valeur', couleur: 'var(--serie-1)', points: evo.map((e) => ({ x: Date.parse(e.t), y: e.valeur })) },
        { nom: 'Versé', couleur: 'var(--serie-2)', pointille: true, points: evo.map((e) => ({ x: Date.parse(e.t), y: e.verse })) },
      ], 130)}</div>` : ''}
    </div>
    <div class="carte"><h2>Positions</h2>${positions ? `<ul class="liste">${positions}</ul>` : '<p class="muet petit">Aucune position.</p>'}</div>
    ${trades ? `<div class="carte"><h2>Derniers trades clôturés</h2><ul class="liste">${trades}</ul></div>` : ''}
    <div class="carte"><details><summary class="gras">La stratégie</summary>
      <p class="petit">${esc(f.resume || r.resume_strategie || '')}</p>${f.inspiration ? `<p class="mini muet">${esc(f.inspiration)}</p>` : ''}
      ${regles('Achète quand', f.regles_achat)}${regles('Vend quand', f.regles_vente)}${regles('Points forts', f.points_forts)}${regles('Points faibles', f.points_faibles)}
    </details></div>
    ${journal ? `<div class="carte"><h2>Journal</h2><ul class="liste">${journal}</ul></div>` : ''}`;
}

function ligneAlerte(a) {
  const c = a.contexte;
  return `<li><details style="padding:10px 0"><summary style="list-style:none;cursor:pointer">
      <div class="entre"><span class="gras petit">${esc(a.titre)}</span>${badge(a.niveau, COULEUR_NIVEAU[a.niveau] || 'gris')}</div>
      <div class="petit">${esc(a.message)}</div><div class="mini muet">${dateHeure(a.declenchee_le)}${a.traitee ? ' · traitée' : ''}</div></summary>
    ${c ? `<div style="margin-top:8px"><div class="ligne"><div class="indice ${c.couleur}">${c.indice_achat_pct ?? '—'}</div><div class="flex petit">Indice d'achat : ${badge(c.verdict || '—', c.couleur)}</div></div>
      ${c.conseil ? `<p class="petit">${esc(c.conseil)}</p>` : ''}${points(c.avantages, 'plus', '+')}${points(c.inconvenients, 'moins', '−')}
      ${a.ticker ? `<p><a href="${lienFiche(a.ticker)}">Voir la fiche complète ›</a></p>` : ''}</div>` : ''}
  </details></li>`;
}

function ligneTache(t) {
  return `<li><div class="element"><div class="flex"><div class="nom" style="white-space:normal">${esc(t.titre)}</div>
      <div class="mini muet">${t.echeance ? `pour le ${dateFr(t.echeance)}` : ''}${t.jours_restants != null && t.statut !== 'fait' ? ` · ${t.jours_restants >= 0 ? `dans ${t.jours_restants} j` : `${-t.jours_restants} j de retard`}` : ''}</div></div>
    ${badge(t.statut_libelle || t.statut, COULEUR_STATUT[t.statut] || 'gris')}</div></li>`;
}

function pageAlertes(d) {
  const alertes = d.alertes || [];
  return `<p><a href="#/plus">‹ Plus</a></p><h1>Alertes</h1>
    <p class="mini muet">Les signaux techniques sont des opportunités à examiner. Touche une alerte pour voir son analyse.</p>
    <div class="carte">${alertes.length ? `<ul class="liste">${alertes.map(ligneAlerte).join('')}</ul>` : '<p class="muet">Aucune alerte.</p>'}</div>`;
}

function pageTaches(d) {
  const t = [...(d.taches || [])].sort((a, b) => (a.echeance || '9').localeCompare(b.echeance || '9'));
  return `<p><a href="#/plus">‹ Plus</a></p><h1>Tâches</h1>
    <div class="carte"><ul class="liste">${t.map(ligneTache).join('') || '<li class="muet">Aucune tâche.</li>'}</ul></div>
    <p class="mini muet">Pour cocher une tâche, utilise le Cockpit du PC.</p>`;
}

const FILTRES_ACTUS = [['tout', 'Tout'], ['miennes', 'Mes actions'], ['importantes', 'Importantes'], ['marches', 'Marchés'], ['monde', 'Monde']];
function pageActus(d) {
  const f = etat.filtreActus;
  const garder = { tout: () => true, miennes: (a) => a.concerne_detenue || a.tickers?.length, importantes: (a) => a.majeure || a.importante,
    marches: (a) => a.categorie === 'marches', monde: (a) => a.categorie === 'monde' }[f] || (() => true);
  const actus = (d.actualites || []).filter(garder);
  return `<p><a href="#/plus">‹ Plus</a></p><h1>Actualités</h1>
    <div class="filtres">${FILTRES_ACTUS.map(([k, n]) => `<button data-filtre="${k}" class="${k === f ? 'actif' : ''}">${n}</button>`).join('')}</div>
    <div class="carte">${actus.length ? `<ul class="liste">${actus.map((a) => `<li style="padding:10px 0">
      <a href="${esc(a.url)}" target="_blank" rel="noopener" class="gras" style="color:inherit;text-decoration:none">${a.majeure || a.importante ? '🔴 ' : ''}${esc(a.titre)}</a>
      <div class="mini muet">${esc(a.source)} · ${dateHeure(a.publie_le)}${a.tickers?.length ? ` · ${esc(a.tickers.join(', '))}` : ''}</div>
      ${a.resume ? `<details><summary class="mini muet">Résumé</summary><p class="petit">${esc(a.resume)}</p></details>` : ''}</li>`).join('')}</ul>` : '<p class="muet">Aucune actualité pour ce filtre.</p>'}</div>`;
}

function pageLecture(d) {
  const jours = d.point_lecture || [];
  return `<p><a href="#/plus">‹ Plus</a></p><h1>Point lecture</h1>
    <p class="mini muet">L'essentiel de chaque jour, sur 7 jours.</p>
    ${jours.map((j) => `<div class="carte"><h2>${esc(j.jour || '')} ${dateFr(j.date)}</h2>
      ${(j.lignes || []).map((l) => `<p class="petit">${esc(l)}</p>`).join('')}
      ${(j.details?.a_la_une || []).length ? `<details><summary class="mini muet">Articles à la une</summary><ul class="liste">${j.details.a_la_une.map((a) => `<li class="petit" style="padding:6px 0"><a href="${esc(a.url)}" target="_blank" rel="noopener">${esc(a.titre)}</a> <span class="mini muet">${esc(a.source)}</span></li>`).join('')}</ul></details>` : ''}
    </div>`).join('') || vide('Pas encore de point lecture.')}`;
}

function pageCalendrier(d) {
  const ev = d.calendrier || [];
  const ICONES = { resultats: '📊', banque_centrale: '🏦', dividende: '💶' };
  return `<p><a href="#/plus">‹ Plus</a></p><h1>Calendrier</h1>
    <div class="carte">${ev.length ? `<ul class="liste">${ev.map((e) => `<li><div class="element">
      <div class="indice" style="font-size:12px;flex-direction:column;line-height:1.1"><span>${jourSemaine(e.date)}</span><span>${dateCourte(e.date)}</span></div>
      <div class="flex"><div class="nom" style="white-space:normal">${ICONES[e.type] || '📅'} ${esc(e.titre)}</div>${e.detenue ? '<div class="mini att">Tu détiens ce titre</div>' : ''}</div></div></li>`).join('')}</ul>` : '<p class="muet">Rien d\'annoncé.</p>'}</div>`;
}

const NOMS_FAMILLES = { tech: 'Technologie', materiaux: 'Matériaux', services_publics: 'Services publics', banques: 'Banques', industrie: 'Industrie',
  sante: 'Santé', finance_holding: 'Holdings', conso_cyclique: 'Conso. cyclique', conso_base: 'Conso. de base', immobilier: 'Immobilier',
  telecom: 'Télécoms', luxe: 'Luxe', assurance: 'Assurance', defense: 'Défense', auto: 'Automobile', energie: 'Énergie', semi: 'Semi-conducteurs' };
function pageMonde(d) {
  const m = d.monde;
  if (!m) return vide('Lecture du monde indisponible.');
  const ligne = (nom, valeur, detail = '') => `<div class="entre petit" style="padding:5px 0;border-top:1px solid var(--bord)"><span>${nom}</span><span class="gras" style="text-align:right">${esc(valeur ?? '—')}${detail ? ` <span class="mini muet">${detail}</span>` : ''}</span></div>`;
  const familles = Object.entries(m.force_familles_3m || {}).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...familles.map(([, v]) => Math.abs(v)));
  return `<p><a href="#/plus">‹ Plus</a></p><h1>Lecture du monde</h1>
    <p class="mini muet">Ce que lisent les robots « grands investisseurs ». Calcul du ${dateFr(m.date)}.</p>
    <div class="carte">
      ${ligne('Marché européen', m.phase, `${pct(m.marche_vs_mm200_pct)} vs MM200`)}
      ${ligne('Peur (VIX)', m.peur, nombre(m.vix))}
      ${ligne('Liquidité', m.liquidite, `taux 10 ans ${nombre(m.taux_10a)} %`)}
      ${ligne('Croissance', m.croissance)}
      ${ligne('Inflation', m.inflation, `Brent ${nombre(m.brent)} $`)}
      ${ligne('Climat (Dalio)', m.quadrant)}
      ${m.choc_energie ? '<p class="petit att">⚡ Choc énergétique en cours.</p>' : ''}
    </div>
    <div class="carte"><h2>Force des secteurs (3 mois, vs marché)</h2>
      ${familles.map(([k, v]) => `<div class="critere" style="grid-template-columns:1fr 1fr 52px"><span class="tronque">${NOMS_FAMILLES[k] || k}</span>
        <div class="barre"><i style="width:${(Math.abs(v) / max) * 100}%;background:var(--${v >= 0 ? 'vert' : 'rouge'})"></i></div>
        <span class="chiffres mini ${signe(v)}" style="text-align:right">${pct(v)}</span></div>`).join('')}</div>`;
}

function pagePlus(d) {
  const nbAlertes = (d.alertes || []).filter((a) => !a.traitee).length;
  const entrees = [['#/alertes', '🔔', 'Alertes', nbAlertes ? `${nbAlertes} à traiter` : ''], ['#/actus', '📰', 'Actualités', ''],
    ['#/lecture', '☕', 'Point lecture', 'l\'essentiel de chaque jour'], ['#/calendrier', '📅', 'Calendrier', 'résultats, banques centrales'],
    ['#/taches', '✅', 'Tâches', ''], ['#/monde', '🌍', 'Lecture du monde', 'climat de marché'], ['#/reglages', '⚙️', 'Réglages', '']];
  return `<h1>Plus</h1><div class="carte"><ul class="liste">${entrees.map(([h, i, n, s]) => `<li><a class="element" href="${h}">
    <div class="indice">${i}</div><div class="flex"><div class="nom">${n}</div>${s ? `<div class="mini muet">${s}</div>` : ''}</div></a></li>`).join('')}</ul></div>`;
}

function pageReglages(d) {
  const theme = stock.lire(CLE_THEME) || 'systeme';
  const memorise = !!stock.lire(CLE_SECRET);
  return `<p><a href="#/plus">‹ Plus</a></p><h1>Réglages</h1>
    <div class="carte"><h2>Thème</h2><div class="filtres">${[['systeme', 'Comme le téléphone'], ['light', 'Clair'], ['dark', 'Sombre']].map(([k, n]) => `<button data-theme-choix="${k}" class="${k === theme ? 'actif' : ''}">${n}</button>`).join('')}</div></div>
    <div class="carte"><h2>La copie</h2>
      <p class="petit">Copie faite par le PC le <strong>${dateHeure(d.genere_le)}</strong>. Le PC en publie une nouvelle toutes les 15 min (de 7h à minuit) quand quelque chose change, s'il est allumé.</p>
      <p class="petit muet">Les cours sont différés d'environ 15 min. Cette app est en lecture seule : les saisies se font dans le Cockpit du PC.</p>
      <p class="petit muet">Les données sont chiffrées (AES-256) : sans ton mot de passe, le fichier publié est illisible.</p></div>
    <div class="carte"><h2>Mot de passe</h2>
      <p class="petit">${memorise ? 'Mémorisé sur ce téléphone.' : 'Pas mémorisé : il sera redemandé à chaque ouverture.'}</p>
      <button class="bouton large" data-oublier>Oublier le mot de passe sur ce téléphone</button></div>`;
}

function pageVerrou() {
  return `<div class="verrou"><div class="logo">🔒</div><h1>Cockpit PEA</h1>
    <p class="muet">Tes données sont chiffrées. Entre le mot de passe choisi dans le Cockpit du PC (Paramètres → App téléphone).</p>
    <form data-verrou>
      <input class="champ" type="password" name="mdp" autocomplete="current-password" placeholder="Mot de passe" required autofocus>
      <label class="case"><input type="checkbox" name="souvenir" checked> Se souvenir sur ce téléphone</label>
      <button class="bouton principal large" type="submit">Ouvrir</button>
      <p class="petit neg" data-erreur></p>
    </form></div>`;
}

// ---------------------------------------------------------------- routes et affichage
const ONGLETS = [['#/', '🏠', 'Accueil'], ['#/actions', '💼', 'Actions'], ['#/top', '🏅', 'Top 5'], ['#/robots', '🤖', 'Robots'], ['#/plus', '☰', 'Plus']];
const SOUS_PLUS = ['alertes', 'actus', 'lecture', 'calendrier', 'taches', 'monde', 'reglages'];

function majEntete() {
  const sous = $('#sous-titre');
  const d = etat.d;
  let texte = etat.chargement ? 'Mise à jour…' : '';
  if (!etat.chargement && d?.genere_le) {
    const age = ageHeures(d.genere_le);
    texte = `Copie du ${jourSemaine(d.genere_le)} ${dateHeure(d.genere_le)}${age > VIEILLE_H ? ' · ancienne (PC éteint ?)' : ''}`;
    sous.className = age > VIEILLE_H ? 'att' : '';
  }
  sous.textContent = texte;
  $('#actualiser').innerHTML = `<span class="${etat.chargement ? 'tourne' : ''}">⟳</span>`;
  $('#masquer').textContent = etat.masque ? '🙈' : '👁';
  $('#masquer').hidden = !d;
}

function rendre() {
  majEntete();
  const app = $('#app');
  const nav = $('#onglets');
  if (!etat.d) {
    nav.hidden = true;
    if (etat.enveloppe) app.innerHTML = pageVerrou();
    else app.innerHTML = etat.erreur ? `<div class="message erreur">${esc(etat.erreur)}</div>` : '<p class="vide">Chargement de la copie…</p>';
    return;
  }
  nav.hidden = false;
  const [, page = '', param] = (location.hash || '#/').split('/');
  const d = etat.d;
  const pages = {
    '': () => pageAccueil(d), actions: () => pageActions(d), fiche: () => pageFiche(d, decodeURIComponent(param || '')),
    top: () => pageTop(d), robots: () => pageRobots(d), robot: () => pageRobot(d, param), plus: () => pagePlus(d),
    alertes: () => pageAlertes(d), actus: () => pageActus(d), lecture: () => pageLecture(d), calendrier: () => pageCalendrier(d),
    taches: () => pageTaches(d), monde: () => pageMonde(d), reglages: () => pageReglages(d),
  };
  let html;
  try { html = (pages[page] || pages[''])(); } catch (e) { html = `<div class="message erreur">Affichage impossible : ${esc(e.message)}</div>`; }
  app.innerHTML = (etat.erreur ? `<div class="message attention">${esc(etat.erreur)}</div>` : '') + html;
  const onglet = page === 'fiche' ? 'actions' : page === 'robot' ? 'robots' : SOUS_PLUS.includes(page) ? 'plus' : page;
  const nbAlertes = (d.alertes || []).filter((a) => !a.traitee).length;
  nav.innerHTML = ONGLETS.map(([h, i, n]) => `<a href="${h}" class="${h === `#/${onglet}` ? 'actif' : ''}"><span>${i}</span>${n}${h === '#/plus' && nbAlertes ? `<em class="pastille">${nbAlertes}</em>` : ''}</a>`).join('');
}

function appliquerTheme() {
  const t = stock.lire(CLE_THEME);
  if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
  else delete document.documentElement.dataset.theme;
}

// ---------------------------------------------------------------- événements
document.addEventListener('submit', async (ev) => {
  const form = ev.target.closest('[data-verrou]');
  if (!form) return;
  ev.preventDefault();
  const bouton = form.querySelector('button');
  bouton.disabled = true;
  bouton.textContent = 'Déchiffrement…';
  try {
    await deverrouiller(form.mdp.value, form.souvenir.checked);
    rendre();
  } catch {
    form.querySelector('[data-erreur]').textContent = 'Mot de passe incorrect.';
    bouton.disabled = false;
    bouton.textContent = 'Ouvrir';
  }
});

document.addEventListener('click', (ev) => {
  const filtre = ev.target.closest('[data-filtre]');
  if (filtre) { etat.filtreActus = filtre.dataset.filtre; rendre(); return; }
  const theme = ev.target.closest('[data-theme-choix]');
  if (theme) { stock.ecrire(CLE_THEME, theme.dataset.themeChoix === 'systeme' ? null : theme.dataset.themeChoix); appliquerTheme(); rendre(); return; }
  if (ev.target.closest('[data-oublier]')) { stock.ecrire(CLE_SECRET, null); etat.cle = null; etat.d = null; rendre(); return; }
  if (ev.target.closest('#actualiser')) actualiser();
  if (ev.target.closest('#masquer')) { etat.masque = !etat.masque; rendre(); }
});

window.addEventListener('hashchange', () => { rendre(); window.scrollTo(0, 0); });
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && Date.now() - etat.derniereLecture > 2 * 60 * 1000) actualiser(true);
});

// ---------------------------------------------------------------- démarrage : dernière copie du téléphone, puis réseau
(async () => {
  appliquerTheme();
  try {
    const garde = JSON.parse(stock.lire(CLE_ENVELOPPE) || 'null');
    if (garde) await ouvrir(garde);
  } catch { /* copie locale illisible : on attend le réseau */ }
  rendre();
  actualiser(true);
})();
