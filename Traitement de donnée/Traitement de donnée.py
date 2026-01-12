#!/usr/bin/env python3
# prog_reseau_gui.py

# Import des bibliothèques graphiques pour créer la fenêtre, les boutons,
# les boîtes de dialogue de sélection de fichier et les messages d’alerte.
import tkinter as tk
from tkinter import filedialog, messagebox

# Import des modules standards pour les expressions régulières, le CSV,
# les statistiques simples (compteurs) et la gestion des chemins de fichiers.
import re
import csv
from collections import Counter, defaultdict
import os

# Import de matplotlib pour générer les graphiques (barres, histogrammes, camemberts).
import matplotlib.pyplot as plt

# Import de la fonction qui construit le rapport final (en Markdown/HTML).
from rapport_md import generer_html

# -----------------------
# 0. Création dossier
# -----------------------

def get_output_dir():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(base_dir, "Fichier d'analyse")
    os.makedirs(out_dir, exist_ok=True)
    return out_dir


# -----------------------
# 1. Sélecteur de fichier
# -----------------------

def choisir_fichier_reseau():
    # Ouvre une boîte de dialogue pour choisir un fichier texte réseau (.txt).
    chemin_fichier = filedialog.askopenfilename(
        title="Sélectionner un fichier texte réseau",
        filetypes=[("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*")]
    )
    # Renvoie le chemin du fichier sélectionné (ou une chaîne vide si annulé).
    return chemin_fichier


def lire_fichier(chemin):
    with open(chemin, "r", encoding="utf-8") as f:
        return [l.rstrip("\n") for l in f]


# -----------------------
# 2. Parsing des lignes
# -----------------------

# Expression régulière qui reconnaît les lignes tcpdump de type IP
# et capture heure, hôte/port source, hôte/port destination, flags et longueur.
REG_IP = re.compile(
    r'^(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+'
    r'(?P<src>[\w\.-]+)\.(?P<src_port>[\w\d]+)\s*>\s*'
    r'(?P<dst>[\w\.-]+)\.(?P<dst_port>[\w\d]+):\s*'
    r'Flags\s+\[(?P<flags>[^\]]*)\].*?'
    r'length\s+(?P<length>\d+)'
)

def split_host_port(nom):
    # Sépare une chaîne "hôte.port" en (hôte, port).
    parts = nom.split(".")
    if len(parts) >= 2:
        # Tout sauf le dernier élément = hôte.
        host = ".".join(parts[:-1])
        # Dernier élément = port.
        port = parts[-1]
    else:
        # Si pas de point, on considère qu’il n’y a pas de port explicite.
        host = nom
        port = "vide"
    return host, port


def ligne_vers_dict(ligne):
    # Applique l’expression régulière à une ligne brute.
    m = REG_IP.match(ligne)
    if not m:
        # Si la ligne ne correspond pas à un paquet IP, on l’ignore.
        return None
    d = m.groupdict()

    # Récupère les champs source / destination complets.
    src_full = d["src"]
    dst_full = d["dst"]
    # Découpe en hôte + port de secours (cas où tcpdump n’a pas séparé).
    src_host, src_port2 = split_host_port(src_full)
    dst_host, dst_port2 = split_host_port(dst_full)

    # Construit un dictionnaire normalisé pour un paquet IP.
    return {
        "heure": d["time"],
        "src_host": src_host,
        # Utilise le port capturé par la regex sinon le port de secours.
        "src_port": d.get("src_port") or src_port2,
        "dst_host": dst_host,
        "dst_port": d.get("dst_port") or dst_port2,
        "flags": d["flags"],
        "length": int(d["length"]),
    }


def construire_tableau(lignes):
    # Transforme toutes les lignes du fichier en une liste de dictionnaires paquets.
    table = []
    for l in lignes:
        evt = ligne_vers_dict(l)
        if evt is not None:
            table.append(evt)
    return table


def ecrire_csv(table, chemin_csv):
    # Si aucune donnée, ne crée pas de CSV.
    if not table:
        return
    # En‑têtes de colonnes du CSV.
    champs = ["heure", "src_host", "src_port", "dst_host", "dst_port", "flags", "length"]
    # Écriture du fichier CSV avec séparateur ';' (pratique pour Excel FR).
    with open(chemin_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=champs, delimiter=";")
        w.writeheader()
        for e in table:
            w.writerow(e)


def analyser_globale(table):
    # Nombre total de paquets.
    total = len(table)
    # Somme des longueurs de tous les paquets (en octets).
    total_octets = sum(e["length"] for e in table)
    # Renvoie un petit dictionnaire de statistiques globales.
    return {
        "nb_total": total,
        "octets_total": total_octets,
    }


# -----------------------
# 2.3. Statistiques génériques
# -----------------------

def stats_ip_sources(table, top_n=10):
    # Compte le nombre de paquets par IP source.
    c = Counter(e["src_host"] for e in table)
    # Renvoie les top N IP source les plus fréquentes.
    return c.most_common(top_n)


def stats_ip_destinations(table, top_n=10):
    # Compte le nombre de paquets par IP destination.
    c = Counter(e["dst_host"] for e in table)
    return c.most_common(top_n)


def stats_ports(table, top_n=10):
    # Compte le nombre de paquets par port destination (en chaîne).
    c = Counter(str(e["dst_port"]) for e in table)
    return c.most_common(top_n)


def stats_longueurs(table):
    # Renvoie la liste brute des longueurs de paquets (pour les histogrammes).
    return [e["length"] for e in table]


def stats_protocoles(table):
    # Répartition grossière des protocoles en fonction du port destination.
    counts = Counter()
    for e in table:
        port = str(e["dst_port"])
        if port in ("53", "domain"):
            counts["DNS"] += 1
        elif port in ("22", "ssh"):
            counts["SSH"] += 1
        elif port in ("80", "http"):
            counts["HTTP"] += 1
        elif port in ("443", "https"):
            counts["HTTPS"] += 1
        else:
            counts["AUTRES"] += 1
    return counts


# -----------------------
# 2.6. Statistiques SSH
# -----------------------

def filtrer_ssh(table):
    # Garde uniquement les paquets liés au port 22 (SSH).
    ssh_pkts = []
    for e in table:
        if (str(e["src_port"]) == "22" or str(e["dst_port"]) == "22"
            or e["src_port"] == "ssh" or e["dst_port"] == "ssh"):
            ssh_pkts.append(e)
    return ssh_pkts


def stats_ssh_sessions(table):
    """
    Approximation de sessions SSH :
    - clé = (src_host, dst_host)
    - 'client' = côté où le port != 22
    - 'serveur' = côté port 22
    """
    # Dictionnaire de sessions avec structure par défaut.
    sessions = defaultdict(lambda: {
        "pkts": 0,
        "bytes_total": 0,
        "bytes_client": 0,
        "bytes_server": 0,
    })
    # Filtre uniquement le trafic SSH.
    ssh_pkts = filtrer_ssh(table)

    for e in ssh_pkts:
        key = (e["src_host"], e["dst_host"])
        s = sessions[key]
        # Incrémente le nombre de paquets et le volume total.
        s["pkts"] += 1
        s["bytes_total"] += e["length"]

        # Répartition du volume entre côté client et côté serveur.
        if str(e["src_port"]) == "22" or e["src_port"] == "ssh":
            s["bytes_server"] += e["length"]
        else:
            s["bytes_client"] += e["length"]

    return sessions


def stats_flags_ssh(table):
    """
    Répartition des flags TCP pour le trafic SSH (port 22).
    On compte le nombre de paquets contenant chaque lettre (S, F, R, P, A, ...).
    """
    ssh_pkts = filtrer_ssh(table)
    counts = Counter()
    for e in ssh_pkts:
        # On parcourt chaque caractère des flags et on garde les lettres.
        for ch in e["flags"]:
            if ch.isalpha():
                counts[ch] += 1
    return counts


# -----------------------
# 2.9. Génération des graphes
# -----------------------

def plot_bar(labels, values, title, xlabel, ylabel, path):
    # Trace un diagramme en barres et l’enregistre dans un fichier image.
    plt.figure(figsize=(8, 4))
    plt.bar(range(len(labels)), values)
    plt.xticks(range(len(labels)), labels, rotation=45, ha="right")
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


def plot_hist(data, title, xlabel, ylabel, path, bins=20):
    # Trace un histogramme et l’enregistre dans un fichier image.
    plt.figure(figsize=(8, 4))
    plt.hist(data, bins=bins)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


def plot_pie(labels, values, title, path):
    # Trace un camembert et l’enregistre dans un fichier image.
    plt.figure(figsize=(5, 5))
    if sum(values) == 0:
        # Cas sans données : camembert neutre.
        labels = ["Aucune donnée"]
        values = [1]
    plt.pie(values, labels=labels, autopct="%1.1f%%", startangle=90)
    plt.title(title)
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


def generer_graphiques_synthese(table, output_dir):
    # IP sources (nombre de requêtes).
    top_src = stats_ip_sources(table)
    if not top_src:
        top_src = [("Aucune IP", 0)]
    labels_src = [ip for ip, n in top_src]
    values_src = [n for ip, n in top_src]
    img_ip_src = os.path.join(output_dir, "ip_sources.png")
    plot_bar(labels_src, values_src,
             "Top IP source", "IP source", "Nombre de paquets", img_ip_src)

    # Nombre de requêtes par IP source (graphique dédié).
    img_requetes = os.path.join(output_dir, "requetes_par_ip.png")
    plot_bar(labels_src, values_src,
             "Nombre de requêtes par IP source",
             "IP source", "Nombre de requêtes", img_requetes)

    # IP destinations.
    top_dst = stats_ip_destinations(table)
    if not top_dst:
        top_dst = [("Aucune IP", 0)]
    labels_dst = [ip for ip, n in top_dst]
    values_dst = [n for ip, n in top_dst]
    img_ip_dst = os.path.join(output_dir, "ip_destinations.png")
    plot_bar(labels_dst, values_dst,
             "Top IP destination", "IP destination", "Nombre de paquets", img_ip_dst)

    # Ports les plus utilisés.
    top_ports = stats_ports(table)
    if not top_ports:
        top_ports = [("aucun", 0)]
    labels_ports = [p for p, n in top_ports]
    values_ports = [n for p, n in top_ports]
    img_ports = os.path.join(output_dir, "ports_top10.png")
    plot_bar(labels_ports, values_ports,
             "10 ports les plus utilisés", "Port destination", "Nombre de paquets", img_ports)

    # Longueur des paquets.
    lengths = stats_longueurs(table)
    if not lengths:
        lengths = [0]
    img_lengths = os.path.join(output_dir, "longueurs_paquets.png")
    plot_hist(lengths,
              "Distribution de la longueur des paquets",
              "Longueur (octets)", "Nombre de paquets", img_lengths)

    # Répartition des protocoles.
    proto_counts = stats_protocoles(table)
    labels_proto = list(proto_counts.keys())
    values_proto = list(proto_counts.values())
    if not labels_proto:
        labels_proto = ["Aucun"]
        values_proto = [1]
    img_proto = os.path.join(output_dir, "protocoles.png")
    plot_pie(labels_proto, values_proto,
             "Répartition des protocoles (par port destination)", img_proto)

    # Renvoie les chemins des images générées pour construire le rapport.
    return {
        "img_ip_src": img_ip_src,
        "img_ip_dst": img_ip_dst,
        "img_ports": img_ports,
        "img_lengths": img_lengths,
        "img_proto": img_proto,
        "img_requetes": img_requetes,
    }


def generer_graphiques_ssh(table, output_dir):
    # Statistiques de sessions SSH.
    sessions = stats_ssh_sessions(table)
    if not sessions:
        # Si aucune session, on en crée une factice pour garder un graphe valide.
        sessions = {("aucune_session", "ssh"): {
            "pkts": 0,
            "bytes_total": 0,
            "bytes_client": 0,
            "bytes_server": 0,
        }}

    labels_sess = [f"{src}->{dst}" for (src, dst) in sessions.keys()]
    pkts_sess = [s["pkts"] for s in sessions.values()]
    bytes_total = [s["bytes_total"] for s in sessions.values()]
    bytes_client = [s["bytes_client"] for s in sessions.values()]
    bytes_server = [s["bytes_server"] for s in sessions.values()]

    # Nombre de paquets par session SSH (approximation du nombre de sessions actives).
    img_ssh_sessions = os.path.join(output_dir, "ssh_sessions_nb.png")
    plot_bar(labels_sess, pkts_sess,
             "Paquets par session SSH (approx.)",
             "Session (client -> serveur)", "Nombre de paquets", img_ssh_sessions)

    # Volume client / serveur par session (barres côte à côte).
    img_ssh_volume = os.path.join(output_dir, "ssh_sessions_volume.png")
    plt.figure(figsize=(8, 4))
    x = range(len(labels_sess))
    plt.bar([i - 0.2 for i in x], bytes_client, width=0.4, label="Client -> Serveur")
    plt.bar([i + 0.2 for i in x], bytes_server, width=0.4, label="Serveur -> Client")
    plt.xticks(list(x), labels_sess, rotation=45, ha="right")
    plt.title("Volume échangé par session SSH")
    plt.xlabel("Session (client -> serveur)")
    plt.ylabel("Octets")
    plt.legend()
    plt.tight_layout()
    plt.savefig(img_ssh_volume)
    plt.close()

    # Répartition des flags TCP sur le trafic SSH.
    flags_counts = stats_flags_ssh(table)
    labels_flags = list(flags_counts.keys()) or ["Aucun"]
    values_flags = list(flags_counts.values()) or [1]
    img_ssh_flags = os.path.join(output_dir, "ssh_flags.png")
    plot_pie(labels_flags, values_flags,
             "Répartition des flags TCP (SSH)", img_ssh_flags)

    # Renvoie les chemins des images SSH pour le rapport.
    return {
        "img_ssh_sessions": img_ssh_sessions,
        "img_ssh_volume": img_ssh_volume,
        "img_ssh_flags": img_ssh_flags,
    }


# =======================
# 3. Interface graphique
# =======================

def afficher_resultat(texte_resultat, chemin_csv, chemin_html, stats, output_dir):
    # Active le widget texte pour pouvoir le modifier.
    texte_resultat.config(state="normal")
    # Efface le contenu précédent.
    texte_resultat.delete("1.0", tk.END)
    # Insère un résumé des fichiers générés et des stats globales.
    texte_resultat.insert(
        tk.END,
        f"Fichiers générés dans : {output_dir}\n\n"
        f"- {os.path.basename(chemin_csv)}\n"
        f"- {os.path.basename(chemin_html)}\n\n"
        f"Paquets totaux : {stats['nb_total']}\n"
        f"Octets totaux : {stats['octets_total']}\n"
    )
    # Repasse le widget en lecture seule.
    texte_resultat.config(state="disabled")


def traiter_fichier(texte_resultat):
    # Demande à l’utilisateur de choisir un fichier texte réseau.
    chemin = choisir_fichier_reseau()
    if not chemin:
        # Si l’utilisateur annule, on ne fait rien.
        return

    # Lecture et parsing des lignes.
    lignes = lire_fichier(chemin)
    table = construire_tableau(lignes)

    if not table:
        # Si aucune ligne valide, avertit l’utilisateur.
        messagebox.showwarning("Erreur", "Aucun paquet IP valide n'a été trouvé dans ce fichier.")
        return

    # Dossier de sortie où tout sera sauvegardé.
    output_dir = get_output_dir()

    # Chemins des fichiers de sortie.
    chemin_csv = os.path.join(output_dir, "reseau_analyse.csv")
    chemin_html = os.path.join(output_dir, "rapport_reseau.html")

    # Écriture du CSV et calcul des stats globales.
    ecrire_csv(table, chemin_csv)
    stats = analyser_globale(table)

    # Graphes de synthèse.
    imgs_synthese = generer_graphiques_synthese(table, output_dir)
    # Graphes spécifiques au SSH.
    imgs_ssh = generer_graphiques_ssh(table, output_dir)

    # Génération du rapport (Markdown -> HTML) via la fonction externe.
    generer_html(
        table,
        stats,
        chemin_html,
        nom_source=chemin,
        **imgs_synthese,
        **imgs_ssh,
    )

    # Ouverture automatique du rapport dans le navigateur par défaut.
    import webbrowser
    webbrowser.open_new_tab(chemin_html)

    # Affichage d’un petit résumé dans la zone de texte de la fenêtre.
    afficher_resultat(texte_resultat, chemin_csv, chemin_html, stats, output_dir)
    # Message final de confirmation.
    messagebox.showinfo(
        "Terminé",
        f"Traitement terminé.\nTous les fichiers ont été générés dans :\n{output_dir}"
    )


def main():
    # Création de la fenêtre principale Tkinter.
    global fenetre
    fenetre = tk.Tk()
    fenetre.title("Traitement réseau - SAÉ1.5")
    fenetre.geometry("700x320")

    # Zone de texte où seront affichés les résultats (résumé).
    texte_resultat = tk.Text(fenetre, height=10, width=80)
    texte_resultat.pack(padx=10, pady=10)
    texte_resultat.config(state="disabled")

    # Bouton pour lancer le traitement d’un fichier réseau.
    btn_choisir = tk.Button(
        fenetre,
        text="Choisir un fichier texte réseau",
        command=lambda: traiter_fichier(texte_resultat)
    )
    btn_choisir.pack(pady=10)

    # Bouton pour quitter l’application.
    btn_quitter = tk.Button(fenetre, text="Quitter", command=fenetre.quit)
    btn_quitter.pack(pady=10)

    # Boucle principale de l’interface graphique.
    fenetre.mainloop()


if __name__ == "__main__":
    # Point d’entrée du programme.
    main()
