# LAB — Analyse statique d'un APK Android : OWASP UnCrackable Level 1

## Objectif

Nous avons réalisé une analyse statique complète de l'application OWASP UnCrackable Level 1, sans l'exécuter. L'objectif était d'identifier les vulnérabilités présentes dans le code, les permissions, les composants exposés, et de retrouver le secret caché dans la logique de vérification.

---

## Environnement et outils

| Outil | Usage |
|---|---|
| **JADX GUI** | Décompilation et exploration du code Java |
| **dex2jar** | Conversion DEX → JAR |
| **JD-GUI** | Analyse alternative du JAR |
| `sha256sum` / `Get-FileHash` | Vérification d'intégrité de l'APK |

- **APK analysé :** `UnCrackable-Level1.apk`
- **Source :** OWASP MASTG — https://mas.owasp.org/crackmes/Android/
- **Hash SHA-256 :** noté pour traçabilité

---

## Ce que nous avons fait

### 1. Préparation du workspace

Nous avons créé un dossier de travail dédié, copié l'APK, vérifié qu'il s'agissait bien d'une archive ZIP valide (signature `PK` en début de fichier), listé son contenu et calculé son hash SHA-256 pour la traçabilité du rapport.

### 2. Analyse avec JADX GUI

Nous avons ouvert l'APK dans JADX et exploré sa structure. Dans `AndroidManifest.xml`, nous avons relevé :

- **Package :** `owasp.mstg.uncrackable1`
- **minSdk :** 19 / **targetSdk :** 28
- **Activité principale :** `sg.vantagepoint.uncrackable1.MainActivity`
- **Aucune permission dangereuse déclarée**
- **Aucun composant exporté explicitement**

### 3. Recherche de chaînes sensibles

Nous avons utilisé la recherche globale de JADX pour identifier les éléments sensibles. Nous avons trouvé dans la classe `a` :

- Une clé AES codée en dur : `8d127684cbc37c17616d806cf50473cc`
- Un texte chiffré en Base64 : `5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=`
- La logique de déchiffrement AES/ECB dans `sg.vantagepoint.a.a`

### 4. Conversion DEX → JAR

Nous avons extrait `classes.dex` de l'APK et converti le fichier en JAR avec dex2jar, puis comparé la décompilation JADX et JD-GUI sur les mêmes classes.

### 5. Déchiffrement du secret (Python)

À partir des éléments trouvés statiquement, nous avons reproduit la logique de vérification en Python sans avoir besoin d'un appareil rooté :

```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = bytes.fromhex("8d127684cbc37c17616d806cf50473cc")
cipher_text = base64.b64decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=")
result = unpad(AES.new(key, AES.MODE_ECB).decrypt(cipher_text), AES.block_size)
print(result.decode())  # → I want to believe
```

---

## Résultat

Le secret de l'application est :

```
I want to believe
```

---

## Constats de sécurité

### Constat #1 — Clé AES codée en dur
**Sévérité :** Élevée  
**Localisation :** `sg.vantagepoint.uncrackable1.a` — méthode `b()`  
**Description :** La clé de chiffrement AES est présente en clair dans le code sous forme de chaîne hexadécimale.  
**Impact :** N'importe qui peut extraire la clé et déchiffrer le secret sans exécuter l'application.  
**Remédiation :** Ne jamais stocker de clés cryptographiques dans le code source. Utiliser Android Keystore pour stocker les clés de façon sécurisée.

### Constat #2 — Algorithme AES/ECB sans IV
**Sévérité :** Moyenne  
**Localisation :** `sg.vantagepoint.a.a` — méthode `a()`  
**Description :** Le mode ECB (Electronic Code Book) est utilisé pour le chiffrement AES. Ce mode est déterministe et ne fournit pas de confidentialité sémantique.  
**Impact :** Des blocs de texte clair identiques produisent des blocs chiffrés identiques, facilitant l'analyse.  
**Remédiation :** Utiliser AES/CBC ou AES/GCM avec un vecteur d'initialisation (IV) aléatoire.

### Constat #3 — Logique de vérification entièrement côté client
**Sévérité :** Élevée  
**Localisation :** `sg.vantagepoint.uncrackable1.MainActivity` — méthode `verify()`  
**Description :** La vérification du secret se fait entièrement dans l'application, sans validation serveur. Le secret est présent dans l'APK.  
**Impact :** Un attaquant peut retrouver le secret par analyse statique ou dynamique sans interagir avec un serveur.  
**Remédiation :** Déplacer la logique de vérification côté serveur. L'application envoie l'entrée utilisateur, le serveur confirme ou infirme sans exposer le secret.

---

## Permissions et composants exportés

**Permissions déclarées :** aucune  
**Composants exportés :** aucun composant avec `exported="true"` ni intent-filter secondaire

---

## Comparaison JADX vs JD-GUI

| Aspect | JADX GUI | JD-GUI |
|---|---|---|
| Ressources Android | Accès direct (Manifest, strings.xml) | Non disponible |
| Navigation | Arborescence complète du projet | Structure JAR uniquement |
| Lisibilité du code | Meilleure reconstruction des noms | Noms obfusqués conservés |
| Annotations Android | Bien préservées | Parfois perdues |

Nous avons conclu que **JADX est plus adapté** pour l'analyse d'APK Android, et JD-GUI constitue un outil complémentaire utile pour confirmer certains résultats.

---

## Conclusion

Cette analyse statique nous a permis de retrouver le secret de l'application sans l'exécuter, en identifiant une clé AES codée en dur et en reproduisant la logique de déchiffrement. Les trois constats documentés montrent que la sécurité d'une application mobile ne peut pas reposer uniquement sur l'obscurité du code compilé.
