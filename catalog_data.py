"""
Curated map of endoflife.date product slugs that matter for WEB DEVELOPMENT,
grouped by category, plus OSV ecosystem mappings for CVE lookups.

We INTERSECT these slugs with endoflife.date's live /api/all.json, so any slug
that doesn't actually exist upstream is simply skipped — the categorization is
best-effort and self-correcting. The OSV map only covers products that live in
an OSV ecosystem (npm, PyPI, Packagist, RubyGems, Maven, Go, etc.); operating
systems and servers usually have no OSV package and show CVE as "n/d".
"""

# slug -> category (human label, drives grouping/filtering in the UI)
WEBDEV_CATEGORIES = {
    # Lenguajes y runtimes
    "php": "Lenguaje / Runtime",
    "python": "Lenguaje / Runtime",
    "nodejs": "Lenguaje / Runtime",
    "ruby": "Lenguaje / Runtime",
    "go": "Lenguaje / Runtime",
    "perl": "Lenguaje / Runtime",
    "rust": "Lenguaje / Runtime",
    "elixir": "Lenguaje / Runtime",
    "dotnet": "Lenguaje / Runtime",
    "dotnetfx": "Lenguaje / Runtime",
    "bun": "Lenguaje / Runtime",
    "deno": "Lenguaje / Runtime",

    # Servidores web / proxies / app servers
    "nginx": "Servidor web / Proxy",
    "apache": "Servidor web / Proxy",
    "tomcat": "Servidor de aplicaciones",
    "eclipse-jetty": "Servidor de aplicaciones",
    "caddy": "Servidor web / Proxy",
    "haproxy": "Servidor web / Proxy",
    "varnish": "Cache / Proxy",
    "traefik": "Servidor web / Proxy",
    "envoy": "Servidor web / Proxy",

    # Bases de datos
    "mysql": "Base de datos",
    "mariadb": "Base de datos",
    "postgresql": "Base de datos",
    "mongodb": "Base de datos",
    "redis": "Base de datos / Cache",
    "valkey": "Base de datos / Cache",
    "elasticsearch": "Base de datos / Búsqueda",
    "opensearch": "Base de datos / Búsqueda",
    "sqlite": "Base de datos",
    "cassandra": "Base de datos",
    "couchdb": "Base de datos",

    # Frameworks PHP y CMS
    "laravel": "Framework backend (PHP)",
    "symfony": "Framework backend (PHP)",
    "cakephp": "Framework backend (PHP)",
    "codeigniter": "Framework backend (PHP)",
    "drupal": "CMS",
    "joomla": "CMS",
    "wordpress": "CMS",
    "typo3": "CMS",
    "magento": "E-commerce",
    "moodle": "Plataforma",
    "composer": "Gestor de dependencias",

    # Frameworks backend (otros)
    "django": "Framework backend (Python)",
    "rails": "Framework backend (Ruby)",
    "spring-framework": "Framework backend (Java)",
    "spring-boot": "Framework backend (Java)",

    # Frameworks / librerías frontend
    "angular": "Framework frontend (JS)",
    "angularjs": "Framework frontend (JS)",
    "vue": "Framework frontend (JS)",
    "nuxt": "Framework frontend (JS)",
    "nextjs": "Framework frontend (JS)",
    "ember": "Framework frontend (JS)",
    "bootstrap": "Framework CSS",

    # Contenedores / infra de despliegue web
    "docker-engine": "Infra / Contenedores",
    "kubernetes": "Infra / Contenedores",
}

# slug -> (osv_ecosystem, package_name) for CVE lookups via OSV.dev
OSV_MAP = {
    "laravel": ("Packagist", "laravel/framework"),
    "symfony": ("Packagist", "symfony/symfony"),
    "cakephp": ("Packagist", "cakephp/cakephp"),
    "drupal": ("Packagist", "drupal/core"),
    "typo3": ("Packagist", "typo3/cms-core"),
    "composer": ("Packagist", "composer/composer"),
    "django": ("PyPI", "django"),
    "rails": ("RubyGems", "rails"),
    "angular": ("npm", "@angular/core"),
    "angularjs": ("npm", "angular"),
    "vue": ("npm", "vue"),
    "nextjs": ("npm", "next"),
    "nuxt": ("npm", "nuxt"),
    "ember": ("npm", "ember-source"),
    "bootstrap": ("npm", "bootstrap"),
    "spring-framework": ("Maven", "org.springframework:spring-core"),
    "spring-boot": ("Maven", "org.springframework.boot:spring-boot"),
    "wordpress": ("Packagist", "roots/wordpress"),
}

# Category display order for the UI grouping/sort.
CATEGORY_ORDER = [
    "Lenguaje / Runtime",
    "Framework backend (PHP)",
    "Framework backend (Python)",
    "Framework backend (Ruby)",
    "Framework backend (Java)",
    "Framework frontend (JS)",
    "Framework CSS",
    "Librería JavaScript",
    "Utilidades JS",
    "Gráficos JavaScript",
    "Animación JS",
    "UI / Componentes",
    "Iconos / Tipografía",
    "Mapas / Geo",
    "Backend / SDK",
    "Auth / Seguridad",
    "Datos / Identidad (CL)",
    "CMS",
    "E-commerce",
    "Plataforma",
    "Servidor web / Proxy",
    "Servidor de aplicaciones",
    "Cache / Proxy",
    "Base de datos",
    "Base de datos / Cache",
    "Base de datos / Búsqueda",
    "Gestor de dependencias",
    "Infra / Contenedores",
    "otros",
]

# =========================================================
# Segunda fuente: librerías de desarrollo web del registro npm.
# endoflife.date NO cataloga librerías JS (jQuery UI, D3, Three.js, Moment.js,
# SweetAlert2, etc.), que son justamente las que detecta Wappalyzer en los
# sitios. Estas se traen del registro npm (versiones + fechas) y se cruzan con
# OSV (ecosistema npm) para CVEs.
#
#   npm_package : (nombre para mostrar, categoría)
#
# Los paquetes con scope (@scope/name) se consultan igual; el código los
# URL-encodea. Se omiten a propósito los que ya están en endoflife.date
# (bootstrap, angular, vue, php, nginx...) para no duplicar.
# =========================================================
NPM_LIBRARIES = {
    # Librerías JS de base
    "jquery":                    ("jQuery", "Librería JavaScript"),
    "jquery-ui":                 ("jQuery UI", "Librería JavaScript"),
    "moment":                    ("Moment.js", "Librería JavaScript"),
    "rxjs":                      ("RxJS", "Librería JavaScript"),
    "zone.js":                   ("Zone.js", "Librería JavaScript"),
    "axios":                     ("Axios", "Librería JavaScript"),
    "react":                     ("React", "Framework frontend (JS)"),
    "svelte":                    ("Svelte", "Framework frontend (JS)"),
    "alpinejs":                  ("Alpine.js", "Framework frontend (JS)"),

    # Utilidades
    "lodash":                    ("Lodash", "Utilidades JS"),
    "underscore":                ("Underscore.js", "Utilidades JS"),
    "marked":                    ("Marked", "Utilidades JS"),
    "dayjs":                     ("Day.js", "Utilidades JS"),
    "core-js":                   ("core-js", "Utilidades JS"),

    # Gráficos / visualización
    "d3":                        ("D3.js", "Gráficos JavaScript"),
    "three":                     ("Three.js", "Gráficos JavaScript"),
    "plotly.js":                 ("Plotly", "Gráficos JavaScript"),
    "chart.js":                  ("Chart.js", "Gráficos JavaScript"),
    "paper":                     ("Paper.js", "Gráficos JavaScript"),
    "echarts":                   ("ECharts", "Gráficos JavaScript"),

    # Animación
    "gsap":                      ("GSAP", "Animación JS"),

    # UI / componentes
    "sweetalert2":               ("SweetAlert2", "UI / Componentes"),
    "swiper":                    ("Swiper", "UI / Componentes"),
    "owl.carousel":              ("OWL Carousel", "UI / Componentes"),
    "@fancyapps/ui":             ("FancyBox", "UI / Componentes"),
    "@popperjs/core":            ("Popper.js", "UI / Componentes"),
    "datatables.net":            ("DataTables", "UI / Componentes"),
    "select2":                   ("Select2", "UI / Componentes"),
    "@ng-bootstrap/ng-bootstrap":("ng-bootstrap", "UI / Componentes"),
    "@ng-select/ng-select":      ("ng-select", "UI / Componentes"),
    "angular-datatables":        ("Angular DataTables", "UI / Componentes"),
    "primeng":                   ("PrimeNG", "UI / Componentes"),

    # Iconos / tipografía
    "bootstrap-icons":           ("Bootstrap Icons", "Iconos / Tipografía"),
    "@fortawesome/fontawesome-free": ("Font Awesome", "Iconos / Tipografía"),

    # Mapas / geo
    "@turf/turf":                ("Turf.js", "Mapas / Geo"),
    "@maptiler/sdk":             ("MapTiler SDK", "Mapas / Geo"),
    "leaflet":                   ("Leaflet", "Mapas / Geo"),
    "maplibre-gl":               ("MapLibre GL", "Mapas / Geo"),
    "mapbox-gl":                 ("Mapbox GL", "Mapas / Geo"),

    # CSS / UI frameworks (no en endoflife)
    "material-design-lite":      ("Material Design Lite", "Framework CSS"),
    "tailwindcss":               ("Tailwind CSS", "Framework CSS"),

    # Backend / SDK
    "firebase":                  ("Firebase", "Backend / SDK"),

    # Auth / seguridad
    "@auth0/angular-jwt":        ("Auth0 Angular JWT", "Auth / Seguridad"),

    # Componentes Angular / Material (de proyectos reales auditados)
    "@angular/cdk":              ("Angular CDK", "UI / Componentes"),
    "@angular/material":         ("Angular Material", "UI / Componentes"),
    "@fortawesome/angular-fontawesome": ("Font Awesome (Angular)", "Iconos / Tipografía"),
    "datatables.net-bs5":        ("DataTables (Bootstrap 5)", "UI / Componentes"),
    "tslib":                     ("tslib", "Utilidades JS"),
    "include-media":             ("include-media", "Framework CSS"),

    # Identificadores chilenos (sujeto a análisis de cumplimiento, Ley 19.628/21.459)
    "chilean-rutify":            ("Chilean Rutify (validador RUT)", "Datos / Identidad (CL)"),
}

# OSV usa el ecosistema npm con el mismo nombre del paquete, así que el mapeo
# es directo (no hace falta listarlos en OSV_MAP).


# Paquetes npm que SÍ tienen ciclo de vida formal en endoflife.date.
# Se usa para enlazar, en el reporte de auditoría, la "URL oficial con info de
# EOL" del producto. npm_package -> slug de endoflife.date
NPM_EOL_MAP = {
    "bootstrap": "bootstrap",
    "@angular/core": "angular",
    "@angular/cli": "angular",
    "vue": "vue",
    "react": "react",
    "next": "nextjs",
    "nuxt": "nuxt",
    "express": "express",
    "electron": "electron",
    "typescript": "typescript",
    "node": "nodejs",
}
