"""Generate standalone HTML and exportable scientific figures from measured runs."""
from __future__ import annotations

import base64
import html
import os
from pathlib import Path

os.environ.setdefault('MPLCONFIGDIR', str(Path(__file__).resolve().parents[1] / '.cache/matplotlib'))
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import precision_recall_curve

COLORS = ['#34d5b1', '#6ea8ff', '#ffba69']


def percent(value):
    return '—' if value is None else f'{100 * value:.1f} %'


def image_tag(path: Path, alt):
    encoded = base64.b64encode(path.read_bytes()).decode('ascii')
    return f'<img src="data:image/png;base64,{encoded}" alt="{html.escape(alt)}">'


def build_report(manifest, predictions, traces, importance, out: Path):
    if manifest.get('dataset', 'ROAD') != 'ROAD':
        return build_ctt_report(manifest, out)
    figures = out / 'figures'
    figures.mkdir(exist_ok=True)
    results = manifest['results']
    y = predictions.label.to_numpy()
    plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 10,
                         'axes.spines.top': False, 'axes.spines.right': False,
                         'figure.facecolor': '#ffffff', 'axes.facecolor': '#ffffff'})
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.8), layout='constrained')
    for color, result in zip(COLORS, results):
        name = result['model']
        precision, recall, _ = precision_recall_curve(y, traces[name])
        axes[0].plot(recall, precision, label=f'{name} (AP {result["test"]["pr_auc"]:.3f})', color=color, lw=2)
    axes[0].axhline(y.mean(), color='#7b8596', ls='--', label='Prévalence des attaques')
    axes[0].set(xlabel='Rappel', ylabel='Précision', title='Courbes précision–rappel · test', xlim=(0, 1), ylim=(0, 1.03))
    axes[0].legend(fontsize=8, loc='lower left')
    x = np.arange(len(results))
    axes[1].bar(x - 0.18, [r['test']['recall'] * 100 for r in results], width=0.36, label='Rappel', color='#20ae91')
    axes[1].bar(x + 0.18, [r['test']['false_positive_rate'] * 100 for r in results], width=0.36, label='Fausses alertes', color='#ee9850')
    axes[1].set(xticks=x, xticklabels=[r['model'].replace(' ', '\n') for r in results],
                ylabel='Pourcentage', title='Détection et coût en fausses alertes', ylim=(0, 105))
    axes[1].legend()
    fig.savefig(figures / 'benchmark.png', dpi=160)
    plt.close(fig)
    families = sorted(f for f in results[0]['by_family'] if f != 'benign')
    heat = np.array([[r['by_family'][f]['recall'] for f in families] for r in results])
    fig, ax = plt.subplots(figsize=(max(8, len(families) * 1.7), 3.5), layout='constrained')
    ax.imshow(heat, vmin=0, vmax=1, cmap='YlGnBu', aspect='auto')
    ax.set(xticks=np.arange(len(families)), xticklabels=[f.replace('_', '\n') for f in families],
           yticks=np.arange(len(results)), yticklabels=[r['model'] for r in results],
           title='Rappel sur fenêtres positives, par famille · test')
    for i in range(len(results)):
        for j in range(len(families)):
            support = results[i]['by_family'][families[j]]['positive_windows']
            ax.text(j, i, f'{heat[i,j]:.0%}\n(n={support})', ha='center', va='center',
                    color='white' if heat[i,j] > 0.6 else '#102638', fontsize=9)
    fig.savefig(figures / 'attack_families.png', dpi=160)
    plt.close(fig)
    champion = next(r for r in results if r['model'] == manifest['champion'])
    # Prefer a test capture with enough context; selection is for illustration only.
    examples = [c for c in predictions.capture.unique() if c.startswith('max_speedometer') and 'masquerade' not in c]
    capture = examples[0] if examples else predictions.capture.iloc[-1]
    mask = predictions.capture.to_numpy() == capture
    timeline = predictions.loc[mask]
    scores = traces[champion['model']][mask]
    fig, ax = plt.subplots(figsize=(11, 3.4), layout='constrained')
    ax.plot(timeline.start_seconds, scores, color='#137f88', lw=1.6, label='Score du modèle retenu')
    ax.axhline(champion['threshold'], color='#c75b2a', ls='--', label='Seuil fixé en validation')
    ymin, ymax = ax.get_ylim()
    ax.fill_between(timeline.start_seconds, ymin, ymax, where=timeline.label.to_numpy() == 1,
                    alpha=0.15, color='#d96d6d', step='post', label='Fenêtres avec injection présumée')
    ax.set(xlabel='Temps écoulé (secondes)', ylabel='Score', title=f'Exemple de chronologie · {capture}')
    ax.legend(fontsize=8, loc='upper left')
    fig.savefig(figures / 'timeline.png', dpi=160)
    plt.close(fig)
    top = importance.head(15).iloc[::-1]
    fig, ax = plt.subplots(figsize=(10, 5.5), layout='constrained')
    ax.barh(top.feature, top.importance, color='#238eae')
    ax.set(xlabel="Importance par diminution d'impureté (biaisée, descriptive)", title='Random Forest · 15 caractéristiques principales')
    fig.savefig(figures / 'feature_importance.png', dpi=160)
    plt.close(fig)
    rows = ''
    for r in results:
        m = r['test']
        ci = r['f1_capture_bootstrap_95']
        interval = f'{ci[0]:.2f}–{ci[1]:.2f}' if ci else '—'
        rows += f'<tr><td>{r["model"]}</td><td>{percent(m["precision"])}</td><td>{percent(m["recall"])}</td><td>{m["f1"]:.3f}</td><td>{m["pr_auc"]:.3f}</td><td>{percent(m["false_positive_rate"])}</td><td>{interval}</td></tr>'
    captures = ''
    for capture_name, m in champion['by_capture'].items():
        captures += f'<tr data-capture="{html.escape(capture_name)}"><td>{html.escape(capture_name)}</td><td>{m["positive_windows"]}</td><td>{percent(m["recall"]) if m["positive_windows"] else "—"}</td><td>{m["false_positive_windows"]}</td><td>{m["missed_attack_windows"]}</td></tr>'
    normal_protocol_rows = ''
    for name, protocol in manifest['normal_only_protocol'].items():
        m = protocol['metrics']
        normal_protocol_rows += f'<tr><td>{name}</td><td>{protocol["attack_captures"]}</td><td>{percent(m["recall"])}</td><td>{percent(m["false_positive_rate"])}</td><td>{m["f1"]:.3f}</td></tr>'
    strict_rows = ''
    for result in results:
        operation = result['low_fpr_operation']
        m = operation['test']
        strict_rows += f'<tr><td>{result["model"]}</td><td>{percent(operation["validation"]["false_positive_rate"])}</td><td>{percent(m["recall"])}</td><td>{percent(m["false_positive_rate"])}</td><td>{m["f1"]:.3f}</td></tr>'
    splits = ''.join(f'<div class="split"><strong>{s}</strong><span>{len(c)} captures</span></div>' for s, c in manifest['splits'].items())
    content = f'''<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CAN Sentinel — rapport expérimental</title>
<style>
:root{{--bg:#0b1422;--card:#132137;--ink:#eaf0f8;--muted:#aabbd1;--line:#2c4059;--accent:#52dfbf}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:16px/1.65 system-ui,sans-serif}}
main{{max-width:1180px;margin:auto;padding:44px 28px 70px}}nav{{display:flex;gap:20px;flex-wrap:wrap;margin-bottom:48px;font-size:13px;letter-spacing:.06em}}a{{color:var(--accent)}}
.eyebrow{{color:var(--accent);text-transform:uppercase;letter-spacing:.16em;font-size:12px;font-weight:750}}h1{{font-size:clamp(42px,7vw,76px);line-height:1.05;margin:14px 0 22px;letter-spacing:-.055em}}h2{{font-size:26px;margin:0 0 14px}}p{{max-width:850px;color:var(--muted)}}.lead{{font-size:20px;max-width:790px}}.tag{{display:inline-block;border:1px solid var(--line);border-radius:30px;padding:4px 12px;font-size:12px;margin:0 6px 10px 0}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:30px 0}}.card,section{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:24px}}.card strong{{display:block;font-size:32px;color:var(--accent)}}.card span{{font-size:13px;color:var(--muted)}}section{{margin-top:22px}}.notice{{border-left:3px solid #ffba69;padding:12px 18px;background:#292435;color:#f4d9b8;margin:28px 0}}.scroll{{overflow:auto}}table{{border-collapse:collapse;width:100%;font-size:13px;white-space:nowrap}}th,td{{padding:13px 12px;border-bottom:1px solid var(--line);text-align:left}}th{{color:var(--muted)}}img{{display:block;width:100%;height:auto;border-radius:8px;margin:22px 0}}.splits{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.split{{padding:14px;border:1px solid var(--line);border-radius:8px}}.split strong,.split span{{display:block}}.split span{{color:var(--muted);font-size:13px}}li{{color:var(--muted);margin:8px 0}}input{{width:100%;max-width:440px;background:var(--bg);color:var(--ink);border:1px solid var(--line);padding:12px;border-radius:8px;margin:10px 0 18px}}footer{{font-size:13px;color:var(--muted);margin-top:30px}}code{{background:#0b1422;padding:3px 6px;border-radius:4px}}@media(max-width:700px){{main{{padding:28px 14px}}.grid,.splits{{grid-template-columns:repeat(2,1fr)}}section{{padding:16px}}}}
</style></head><body><main>
<nav><b>CAN / SENTINEL</b><a href="#results">Résultats</a><a href="#protocol">Protocole</a><a href="#captures">Captures</a><a href="#limits">Limites</a></nav>
<div class="eyebrow">Automotive cybersecurity · benchmark reproductible</div>
<h1>Détecter l'intrusion.<br>Mesurer les limites.</h1>
<p class="lead">Détection hors ligne d'anomalies dans le réseau CAN d'un véhicule. Trois approches confrontées à de vraies captures ROAD, avec séparation des enregistrements et seuils fixés avant le test.</p>
<span class="tag">Données réelles · ORNL</span><span class="tag">Fenêtres de 500 ms</span><span class="tag">CPU · Python</span><span class="tag">Aucune action sur un véhicule</span>
<div class="grid"><div class="card"><strong>{manifest['raw_frames']/1e6:.1f} M</strong><span>messages lus dans les 45 fichiers, variantes comprises</span></div><div class="card"><strong>{manifest['feature_windows']:,}</strong><span>fenêtres observées, tous lots compris</span></div><div class="card"><strong>{len(manifest['splits']['test'])}</strong><span>captures de test</span></div><div class="card"><strong>{champion['test']['f1']:.3f}</strong><span>F1 de test · modèle choisi en validation</span></div></div>
<div class="notice">Étude exploratoire : les résultats de test ont été consultés pendant le développement. Prototype sur un seul véhicule anonymisé, avec labels reconstruits et variantes masquerade dérivées. Aucune protection opérationnelle n'est démontrée.</div>
<section id="results"><div class="eyebrow">01 / Résultats mesurés</div><h2>Trois modèles, un même test</h2>
<p>Modèle retenu : <b>{champion['model']}</b>, choisi pour son F1 en validation. Le réglage principal maximise le F1 de validation : il accepte davantage de fausses alertes. Les labels d'attaque de validation servent au choix du seuil des trois modèles.</p>
<div class="scroll"><table><thead><tr><th>Modèle</th><th>Précision</th><th>Rappel</th><th>F1</th><th>PR-AUC / AP</th><th>Fausses alertes</th><th>IC 95 % F1*</th></tr></thead><tbody>{rows}</tbody></table></div>
<p>* Bootstrap des groupes de captures sources, 400 tirages. Intervalles exploratoires sur un petit nombre d'enregistrements ; les variantes d'une même capture sont rééchantillonnées ensemble.</p>
<h2>Autre réglage : privilégier les faibles fausses alertes</h2><p>Seuils fixés pour au plus 1 % de fausses alertes en validation. Le test peut s'écarter fortement de ce budget : c'est une mesure du changement de conditions, pas une garantie.</p>
<div class="scroll"><table><tr><th>Modèle</th><th>Fausses alertes validation</th><th>Rappel test</th><th>Fausses alertes test</th><th>F1 test</th></tr>{strict_rows}</table></div>
{image_tag(figures / 'benchmark.png', 'Courbes précision rappel et comparaison des fausses alertes')}
{image_tag(figures / 'attack_families.png', 'Rappel par famille avec effectifs de fenêtres positives')}
<p>La famille coolant n'est présente qu'au test : elle illustre une attaque non vue par le modèle supervisé. Les scores sur peu de fenêtres positives restent fragiles.</p></section>
<section id="protocol"><div class="eyebrow">02 / Méthode</div><h2>Une séparation par captures sources</h2><div class="splits">{splits}</div>
<ol><li>Lecture des 45 captures brutes directement dans l'archive vérifiée ; suppression de l'identifiant d'anonymisation FFF, pas d'échantillonnage des messages.</li>
<li>Fenêtres temporelles disjointes de 0,5 seconde : fréquence par identifiant, temps intermessages et statistiques des huit octets de données. Les fenêtres sans message ne sont pas créées.</li>
<li>Vocabulaire d'identifiants appris sur les captures normales d'entraînement. Les identifiants nouveaux sont regroupés dans une proportion explicite.</li>
<li>Robust profile et Isolation Forest ajustés sur le trafic normal uniquement. Random Forest entraînée sur les captures normales et les premières répétitions d'attaques.</li>
<li>Seuils réglés sur la validation. Troisièmes répétitions et attaque coolant gardées au test. Variantes fabrication / masquerade toujours dans le même lot.</li></ol>
<p>Le profil robuste mesure les écarts aux plages normales ; Isolation Forest recherche des observations atypiques ; Random Forest apprend une classification avec les labels disponibles. Aucun nom de capture, label, instant absolu ou paramètre d'injection n'entre dans les caractéristiques.</p>
<h2>Protocole complémentaire sans attaques d'apprentissage</h2><p>Les deux modèles non supervisés sont aussi évalués sur toutes les captures d'injection et le trafic normal du test, avec un seuil calibré sur les seules captures normales de validation. Aucun label d'attaque ne sert à choisir ce seuil. Les variantes restent corrélées : ce protocole n'est pas une preuve de généralisation à un autre véhicule.</p>
<div class="scroll"><table><tr><th>Modèle</th><th>Captures d'injection</th><th>Rappel</th><th>Fausses alertes</th><th>F1</th></tr>{normal_protocol_rows}</table></div></section>
<section><div class="eyebrow">03 / Inspection</div><h2>Voir le comportement dans le temps</h2>{image_tag(figures / 'timeline.png', 'Score et seuil au cours d’une capture de test')}
<p>Le score est disponible à la fin d'une fenêtre. Toute estimation de délai à partir du début de fenêtre est discrétisée et doit ajouter le temps d'attente de la fenêtre et de calcul.</p>
{image_tag(figures / 'feature_importance.png', 'Caractéristiques importantes de la forêt supervisée')}
<p>Les importances par impureté décrivent le modèle et sont biaisées vers certaines variables ; elles ne constituent pas une explication causale.</p></section>
<section id="captures"><div class="eyebrow">04 / Détail des erreurs</div><h2>Inspecter les captures du test</h2><label for="filter">Filtrer par nom de capture</label><br><input id="filter" type="search" placeholder="Exemple : masquerade, ambient, coolant…">
<div class="scroll"><table><thead><tr><th>Capture</th><th>Fenêtres positives</th><th>Rappel</th><th>Fausses alertes</th><th>Fenêtres d'attaque manquées</th></tr></thead><tbody id="capture-rows">{captures}</tbody></table></div></section>
<section id="limits"><div class="eyebrow">05 / Lecture critique</div><h2>Ce que ces résultats permettent d'affirmer</h2><ul>
<li>Les performances concernent des fenêtres de captures ROAD d'un seul véhicule ; aucune validation multi-véhicule ou sur véhicule réel n'est revendiquée.</li>
<li>Les labels reconstruits par intervalle, identifiant et données peuvent confondre une trame légitime et une injection identique. La fenêtre est positive dès qu'un message correspond.</li>
<li>Les quatre captures accelerator, sans labels d'injection exploitables, sont exclues des métriques binaires. Leur taux d'alerte est enregistré séparément dans le manifeste.</li>
<li>Les captures présentent un déséquilibre important entre trafic normal et attaques. Le F1 et la PR-AUC dépendent de cette prévalence.</li>
<li>Les calculs de débit portent sur les caractéristiques déjà extraites. Ce traitement hors ligne n'est pas un benchmark temps réel embarqué.</li>
<li>Les captures vides et les périodes sans message ne produisent pas de fenêtres : la détection d'une disparition complète du trafic est hors périmètre.</li>
<li>Les mesures can-train-and-test sont présentées dans un <a href="ctt/index.html">rapport complémentaire distinct</a> ; elles ne sont pas mélangées aux résultats ROAD.</li></ul>
<p>Source : <a href="https://zenodo.org/records/10462796">ROAD, ORNL — CC BY 4.0</a>. Référence : <a href="https://doi.org/10.1371/journal.pone.0296879">Verma et al., PLOS ONE, 2024</a>. Téléchargement et contrôle d'intégrité documentés dans le dépôt.</p></section>
<footer>CAN Sentinel · données et expériences traçables · Seed {manifest['seed']} · Python {manifest['python']} · scikit-learn {manifest['sklearn']}<br>Fichiers associés : experiment.json, metrics.csv, test_predictions.csv et figures/.</footer>
</main><script>document.getElementById('filter').addEventListener('input',function(){{const q=this.value.toLowerCase();document.querySelectorAll('[data-capture]').forEach(row=>row.hidden=!row.dataset.capture.toLowerCase().includes(q));}});</script></body></html>'''
    (out / 'index.html').write_text(content, encoding='utf-8')
    lines = ['# CAN Sentinel — résultats mesurés', '',
             f"Modèle choisi en validation : **{manifest['champion']}**.", '',
             '| Modèle | Précision | Rappel | F1 | PR-AUC (AP) | Fausses alertes |',
             '|---|---:|---:|---:|---:|---:|']
    for r in results:
        m = r['test']
        lines.append(f'| {r["model"]} | {percent(m["precision"])} | {percent(m["recall"])} | {m["f1"]:.3f} | {m["pr_auc"]:.3f} | {percent(m["false_positive_rate"])} |')
    lines += ['', f"{manifest['raw_frames']:,} messages lus, variantes comprises ; {manifest['feature_windows']:,} fenêtres.", '',
              'Labels reconstruits ; un seul véhicule ; variantes de captures corrélées ; accelerator exclu des métriques binaires.',
              'Consulter le rapport HTML pour le protocole complet, les résultats par famille et les limites.']
    (out / 'RESULTS_FR.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')


def build_ctt_report(manifest, out):
    rows = ''
    comparison = []
    for result in manifest['results']:
        for scenario, m in result.get('by_scenario', {}).items():
            rows += (f'<tr><td>{result["model"]}</td><td>{html.escape(scenario)}</td>'
                     f'<td>{m["windows"]}</td><td>{percent(m["precision"])}</td><td>{percent(m["recall"])}</td>'
                     f'<td>{m["f1"]:.3f}</td><td>{percent(m["false_positive_rate"])}</td></tr>')
            comparison.append(dict(model=result['model'], scenario=scenario, **m))
    import pandas as pd
    pd.DataFrame(comparison).to_csv(out / 'scenario_metrics.csv', index=False)
    scenarios = sorted(manifest['results'][0]['by_scenario'])
    fig, ax = plt.subplots(figsize=(11, 4), layout='constrained')
    x = np.arange(len(scenarios))
    for i, result in enumerate(manifest['results']):
        scores = [result['by_scenario'][s]['f1'] for s in scenarios]
        ax.bar(x + (i-1)*0.24, scores, width=0.24, label=result['model'], color=COLORS[i])
    ax.set(xticks=x, xticklabels=['Véhicule connu\nattaque connue', 'Véhicule inconnu\nattaque connue',
                                 'Véhicule connu\nattaque inconnue', 'Véhicule inconnu\nattaque inconnue'],
           ylabel='F1 sur fenêtres de 500 ms', title='can-train-and-test · sous-ensemble set_01', ylim=(0, 1.12))
    ax.legend(fontsize=8)
    (out / 'figures').mkdir(exist_ok=True)
    fig.savefig(out / 'figures/scenarios.png', dpi=160)
    plt.close(fig)
    transfer = ''
    transfer_path = out / 'road_transfer.json'
    if transfer_path.exists():
        import json
        t = json.loads(transfer_path.read_text(encoding='utf-8'))
        m = t['metrics']
        transfer = f'<h2>Transfert direct du modèle ROAD, sans adaptation</h2><p>F1 : {m["f1"]:.3f} ; rappel : {percent(m["recall"])} ; fausses alertes : {percent(m["false_positive_rate"])} ; proportion moyenne d’identifiants inconnus : {percent(t["mean_unknown_id_fraction"])}.</p><p>Les identifiants CAN et leurs signaux dépendent du véhicule. Transférer un modèle appris sur des identifiants anonymisés ROAD ne garantit pas un sens commun des variables. Ce test mesure cette difficulté ; il ne remplace pas une adaptation au véhicule.</p>'
    content = f'''<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CAN Sentinel — deuxième dataset</title>
<style>body{{font:16px/1.65 system-ui;background:#0b1422;color:#eaf0f8;margin:0}}main{{max-width:1150px;margin:auto;padding:40px 24px}}h1{{font-size:44px;line-height:1.1}}h2{{color:#52dfbf}}p,li{{color:#b8c8dc}}a{{color:#52dfbf}}table{{border-collapse:collapse;width:100%;font-size:13px;white-space:nowrap}}td,th{{padding:12px;border-bottom:1px solid #2c4059;text-align:left}}.scroll{{overflow:auto}}img{{width:100%;border-radius:10px}}.notice{{border-left:3px solid #ffba69;background:#292435;padding:16px}}</style></head>
<body><main><a href="../index.html">← Rapport ROAD</a><p>CAN / SENTINEL · VALIDATION COMPLÉMENTAIRE</p><h1>Changer de véhicule.<br>Changer d'attaque.</h1>
<p>Benchmark local sur un sous-ensemble documenté de can-train-and-test set_01 : Chevrolet Impala à l'entraînement, Chevrolet Silverado pour les scénarios de véhicule inconnu, selon le README des auteurs.</p>
<p class="notice">Étude exploratoire sur un sous-ensemble, pas une reproduction complète du benchmark publié. Les résultats ne sont pas directement comparables au score ROAD : véhicules, attaques, labels et prévalence diffèrent.</p>
<h2>Protocole fixé avant le test de ce dataset</h2><ul><li>Tous les fichiers du dossier officiel train_01 sont téléchargés. Les répétitions -1 servent à l'entraînement, les répétitions -2 à la validation.</li><li>Pour chacun des quatre dossiers de test, première répétition disponible par famille d'attaque, dans l'ordre lexicographique. Aucune sélection selon les résultats.</li><li>Labels binaires fournis par les auteurs ; fenêtres de 500 ms positives si elles contiennent au moins une trame étiquetée attaque.</li><li>Mêmes caractéristiques et modèles que ROAD, réentraînés localement. Seuils et modèle retenu choisis uniquement sur la validation locale. Aucun ajustement sur les quatre lots de test.</li><li>Contrôle des doublons exacts entre lots par SHA256. Les charges utiles de moins de huit octets sont complétées par des zéros pour ce prototype ; la longueur d'origine n'est pas modélisée.</li></ul>
<p>{manifest['raw_frames']:,} messages traités ; {manifest['feature_windows']:,} fenêtres ; {len(manifest['inventory'])} fichiers. Modèle retenu en validation : <b>{manifest['champion']}</b>.</p>
<p>Qualité temporelle : {sum(i.get('timestamp_backward_steps', 0) for i in manifest['inventory'])} pas d'horodatage négatifs comptés avant tri stable global par capture. Les fichiers originaux sont conservés.</p>
{image_tag(out / 'figures/scenarios.png', 'Comparaison des modèles selon véhicule et attaque connus ou inconnus')}
<div class="scroll"><table><tr><th>Modèle</th><th>Scénario officiel</th><th>Fenêtres</th><th>Précision</th><th>Rappel</th><th>F1</th><th>Fausses alertes</th></tr>{rows}</table></div>
{transfer}<h2>Traçabilité et limites</h2><p>Les fichiers sources ont été téléchargés depuis l'archive officielle par requêtes partielles. Leur CRC ZIP est vérifié et leur SHA256 enregistré. Le MD5 de l'archive entière ne peut pas être vérifié sans la télécharger intégralement. Le manifeste conserve la sélection exacte, la licence, les tailles et les empreintes.</p>
<p>Les faux positifs sont des fenêtres, pas des incidents regroupés. Les sessions d'attaque contiennent du trafic bénin ; elles ne remplacent pas une longue évaluation indépendante en conduite normale. Aucun déploiement embarqué n'a été testé.</p><p><a href="https://doi.org/10.11583/DTU.24805533">Dataset original · CC BY 4.0</a> — Lampe et al., <a href="https://doi.org/10.1016/j.cose.2024.103777">can-train-and-test, 2024</a>.</p></main></body></html>'''
    (out / 'index.html').write_text(content, encoding='utf-8')
    lines = ['# can-train-and-test — évaluation complémentaire', '',
             'Sous-ensemble set_01, sélection fixée avant le test. Modèles réentraînés localement.', '',
             '| Modèle | Scénario | F1 | Rappel | Fausses alertes |', '|---|---|---:|---:|---:|']
    for row in comparison:
        lines.append(f'| {row["model"]} | {row["scenario"]} | {row["f1"]:.3f} | {percent(row["recall"])} | {percent(row["false_positive_rate"])} |')
    (out / 'RESULTS_FR.md').write_text('\n'.join(lines)+'\n', encoding='utf-8')
