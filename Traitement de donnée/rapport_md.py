# rapport_html.py

import markdown  # bibliothèque python-markdown


def generer_html(
    table,
    stats,
    chemin_html,      # chemin du fichier HTML final, ex : rapport_reseau.html
    nom_source,
    img_ip_src,
    img_ip_dst,
    img_ports,
    img_lengths,
    img_proto,
    img_requetes,
    img_ssh_sessions,
    img_ssh_volume,
    img_ssh_flags,
):
    # 1) Contenu du rapport en Markdown
    md = f"""# Analyse des traces réseau

## Résumé du fichier

- **Fichier analysé** : `{nom_source}`
- **Nombre total de paquets analysés** : {stats['nb_total']}
- **Volume total** : {stats['octets_total']} octets

---

## Axes d'analyse recommandés

Ce rapport permet de visualiser rapidement les IP les plus actives, les ports les plus sollicités,
la longueur des paquets et la répartition des protocoles pour identifier des comportements anormaux.

Les informations ci-dessous proviennent de l’analyse du résultat de la commande `tcpdump`,
outil de capture de paquets largement utilisé pour le diagnostic réseau et l’analyse de sécurité.

---

## Vue synthétique du trafic

### Top IP source

![Top IP source]({img_ip_src})

Ce graphique met en évidence les machines qui émettent le plus de requêtes
et permet de repérer rapidement une IP potentiellement à l’origine d’un scan
ou d’un débit inhabituel.

### Top IP destination

![Top IP destination]({img_ip_dst})

Ce graphique montre quelles machines reçoivent le plus de trafic et peut indiquer
une cible de scan, de DDoS ou un serveur fortement sollicité.

### 10 ports les plus utilisés

![Ports les plus utilisés]({img_ports})

La répartition des ports aide à identifier les services les plus exposés (HTTP, HTTPS, SSH, etc.)
et à repérer d’éventuels scans de ports sur des services inattendus.

### Distribution de la longueur des paquets

![Longueur des paquets]({img_lengths})

L’analyse de la taille des paquets permet de voir si le trafic est principalement composé
de petits paquets (scans, SYN) ou de flux plus volumineux (transferts de données).

### Nombre de requêtes par IP source

![Nombre de requêtes]({img_requetes})

Ce graphique résume le nombre total de requêtes par IP source et sert à confirmer ou infirmer
le rôle d’une machine dans une activité suspecte ou anormalement bavarde.

### Répartition des protocoles

![Répartition des protocoles]({img_proto})

La répartition des protocoles indique si le trafic est conforme à l’usage prévu
(web, DNS, SSH) ou s’il contient une proportion inhabituelle de certains services.

---

## Activité SSH

### Sessions SSH approximées

![Sessions SSH]({img_ssh_sessions})

Ce graphique représente, pour chaque couple client → serveur en SSH, le nombre de paquets
observés, ce qui donne une idée du nombre et de l’intensité des sessions actives.

### Volume échangé par session SSH

![Volume SSH par session]({img_ssh_volume})

La comparaison des octets client → serveur et serveur → client par session permet
de repérer des connexions déséquilibrées, par exemple un débit anormal côté serveur.

### Répartition des flags TCP (SSH)

![Flags SSH]({img_ssh_flags})

La répartition des flags (SYN, FIN, RST, PSH, ACK…) sur le trafic SSH aide à repérer
des terminaisons brutales (beaucoup de RST) ou des sessions qui poussent surtout des données.
"""

    # 2) Conversion Markdown -> HTML (corps de page)
    body_html = markdown.markdown(md, extensions=["tables"])

    # 3) Gabarit HTML complet
    page = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Analyse réseau</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      margin: 20px;
      line-height: 1.5;
    }}
    img {{
      max-width: 100%;
      height: auto;
    }}
  </style>
</head>
<body>
{body_html}
</body>
</html>
"""

    # 4) Écriture du fichier HTML final
    with open(chemin_html, "w", encoding="utf-8") as f:
        f.write(page)
