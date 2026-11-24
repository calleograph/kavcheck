# Сторонние компоненты и лицензии

KAV Checker распространяется со следующими сторонними компонентами. Тексты лицензий лежат в образе backend (`/opt/kavcheck/licenses`) и в репозитории (`backend/docker/licenses`).

| Компонент | Версия | Лицензия | Где используется | Как распространяется |
|---|---|---|---|---|
| [Nuclei](https://github.com/projectdiscovery/nuclei) (ProjectDiscovery) | 3.11.1 | MIT | сканер Pentest, образ backend | готовый бинарник релиза; версия и SHA-256 закреплены в `backend/Dockerfile`, сборка останавливается при несовпадении |
| [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | 10.5.1 | MIT | шаблоны проверок Pentest | архив релиза в образе (`/opt/kavcheck/nuclei-templates.tar.gz`), SHA-256 закреплён; распаковывается в том `pentest_data`; обновление — по запросу администратора |
| [Nmap](https://nmap.org) | из пакета Debian | Nmap Public Source License | сканер Pentest | устанавливается пакетом ОС при сборке образа; исходный код и лицензия — у проекта Nmap |
| DejaVu Sans | — | свободная лицензия DejaVu | PDF-отчёты | `backend/app/assets/fonts`, лицензия рядом |
| [MaxMind DB Reader](https://github.com/maxmind/MaxMind-DB-Reader-python) | 3.3.0 проверена | Apache-2.0 | чтение локальных MMDB в worker | пакет `maxminddb` с собственной лицензией |
| [GeoLite2 City, ASN и Country](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) | ежедневная проверка | [GeoLite EULA](https://www.maxmind.com/en/geolite/eula) и [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) в пределах EULA | география сетевого выхода и ASN | worker загружает файлы в установку из [стороннего зеркала P3TERX](https://github.com/P3TERX/GeoLite.mmdb/releases). Поставка включает код загрузчика |
| [DB-IP Lite City и ASN](https://db-ip.com/db/lite.php) | ежемесячные выпуски | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) | география сетевого выхода и организация ASN | при выборе DB-IP worker загружает файлы в установку. Страницы и отчёты с результатами указывают источник DB-IP |
| [Natural Earth Land](https://www.naturalearthdata.com/downloads/110m-physical-vectors/110m-land/) | 1:110m из выпуска 5.1.2 | [public domain](https://www.naturalearthdata.com/about/terms-of-use/) | подложка карты оборудования | геометрия суши в `frontend/public/geo-land.json` из [набора Natural Earth](https://github.com/nvkelso/natural-earth-vector/blob/v5.1.2/geojson/ne_110m_land.geojson) |

Лицензии Nuclei и nuclei-templates (MIT) разрешают использование, копирование и распространение при сохранении уведомления об авторских правах и текста лицензии — они включены в образ. Шаблоны подписаны ProjectDiscovery; Nuclei запускается с `-dut` и не выполняет шаблоны с нарушенной подписью. Обновление движка: измените версию и SHA-256 в `backend/Dockerfile` (ARG `NUCLEI_*`) и выпустите новую версию KAV Checker; шаблоны обновляются отдельно, без пересборки образа.

GeoLite2 создает MaxMind. Загрузка или использование баз означает принятие GeoLite EULA. P3TERX публикует копии и ссылается на условия MaxMind. Управляющий установкой может использовать прямую загрузку MaxMind или подставить собственный источник по условиям GeoLite EULA. Закрытые и публичные отчёты с GeoLite2 сохраняют атрибуцию MaxMind. Условия дальнейшей передачи, актуализации и удаления данных приведены в § 6. [Лицензия GeoLite](https://www.maxmind.com/en/geolite/eula)
