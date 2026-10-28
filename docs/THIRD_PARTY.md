# Сторонние компоненты и лицензии

KAV Checker распространяется со следующими сторонними компонентами. Тексты лицензий лежат в образе backend (`/opt/kavcheck/licenses`) и в репозитории (`backend/docker/licenses`).

| Компонент | Версия | Лицензия | Где используется | Как распространяется |
|---|---|---|---|---|
| [Nuclei](https://github.com/projectdiscovery/nuclei) (ProjectDiscovery) | 3.11.1 | MIT | сканер Pentest, образ backend | готовый бинарник релиза; версия и SHA-256 закреплены в `backend/Dockerfile`, сборка останавливается при несовпадении |
| [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | 10.5.1 | MIT | шаблоны проверок Pentest | архив релиза в образе (`/opt/kavcheck/nuclei-templates.tar.gz`), SHA-256 закреплён; распаковывается в том `pentest_data`; обновление — по запросу администратора |
| [Nmap](https://nmap.org) | из пакета Debian | Nmap Public Source License | сканер Pentest | устанавливается пакетом ОС при сборке образа; исходный код и лицензия — у проекта Nmap |
| DejaVu Sans | — | свободная лицензия DejaVu | PDF-отчёты | `backend/app/assets/fonts`, лицензия рядом |

Лицензии Nuclei и nuclei-templates (MIT) разрешают использование, копирование и распространение при сохранении уведомления об авторских правах и текста лицензии — они включены в образ. Шаблоны подписаны ProjectDiscovery; Nuclei запускается с `-dut` и не выполняет шаблоны с нарушенной подписью. Обновление движка: измените версию и SHA-256 в `backend/Dockerfile` (ARG `NUCLEI_*`) и выпустите новую версию KAV Checker; шаблоны обновляются отдельно, без пересборки образа.
