# THEDAY — scanner de reconnaissance web / mauvaises configurations

Scanner de reconnaissance web qui vérifie sur une cible : les en-têtes de sécurité manquants, les fuites de version (`Server`, `X-Powered-By`...), les cookies sans `Secure`/`HttpOnly`, les chemins sensibles exposés (`.git/config`, `.env`, sauvegardes, `wp-login.php`...), la chaîne de redirections (avec détection de boucle), `robots.txt`/`sitemap.xml`, et l'état du certificat TLS (expiration, protocole obsolète). Peut sauvegarder les ressources trouvées et forcer la résolution DNS vers une IP donnée pour atteindre un serveur d'origine directement (comme `curl --resolve`), Host/SNI/vérification du certificat restant sur le nom réel.
*Web recon scanner for missing security headers, version-disclosure headers, insecure cookie flags, exposed sensitive paths, redirect chains, robots/sitemap hints and TLS certificate issues — with optional file download and DNS override to reach an origin server directly.*

> **Usage autorisé uniquement.** Ne scanner que des hôtes que vous possédez ou pour lesquels vous avez une autorisation explicite (mission de pentest, CTF, bug bounty dans le périmètre). Le scan non autorisé de systèmes tiers peut être illégal selon votre juridiction.

## Usage
```bash
pip install -r requirements.txt
python3 theday.py exemple.com
python3 theday.py https://exemple.com --download ./trouvailles
python3 theday.py exemple.com --resolve 203.0.113.10
```

## Options
| Option | Rôle |
|---|---|
| `target` | URL ou nom d'hôte cible (doit être autorisé pour le test) |
| `--timeout` | Timeout de requête en secondes (défaut 10) |
| `--no-banner` | Supprime la bannière ASCII |
| `--download DIR` | Télécharge les ressources exposées/redirigées trouvées pendant le scan dans ce dossier |
| `--resolve IP` | Force la résolution DNS du nom de la cible vers cette IP (comme `curl --resolve`), pour atteindre un serveur d'origine directement en contournant le DNS d'un CDN/WAF — Host/SNI/vérification du certificat restent sur le nom réel |

## Ce qu'il vérifie
| Signal | Détail |
|---|---|
| En-têtes de sécurité | `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` |
| Fuite de version | `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator` |
| Cookies | Drapeaux `Secure`/`HttpOnly` manquants |
| Chemins sensibles | `.git/config`, `.git/HEAD`, `.env`, sauvegardes `wp-config`/`config.php`, `docker-compose.yml`, `id_rsa`, `phpinfo.php`, `server-status`, `wp-login.php`... |
| Redirections | Chaîne complète suivie manuellement, boucles détectées |
| `robots.txt`/`sitemap.xml` | Signale le nombre d'entrées `Disallow` (chemins potentiellement cachés) |
| TLS | Expiration du certificat (ou déjà expiré), protocole obsolète (TLSv1/1.1) |

## Dépendances
```
requests>=2.31
```
