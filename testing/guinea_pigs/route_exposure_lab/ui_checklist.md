# Route exposure: UI checklist (plan §22.3)

Tick each cell during the campaign; screenshots go in `reports/screenshots/<phase>/`.

## Per field (v1)

| Field | flip/save/reload | `get_recon_settings` | min/max/out-of-bounds | network 2xx/4xx | console clean | screenshot |
| --- | --- | --- | --- | --- | --- | --- |
| routeExposureEnabled | [ ] | [ ] | n/a | [ ] | [ ] | [ ] |
| routeExposureSeedPaths | [ ] | [ ] | n/a | [ ] | [ ] | [ ] |
| routeExposureVcsFiles | [ ] | [ ] | n/a | [ ] | [ ] | [ ] |
| routeExposureBackupFiles | [ ] | [ ] | n/a | [ ] | [ ] | [ ] |
| routeExposureVersionVariants | [ ] | [ ] | n/a | [ ] | [ ] | [ ] |
| routeExposureCompareLoggedIn | [ ] | [ ] | n/a | [ ] | [ ] | [ ] |
| routeExposurePiiDetection | [ ] | [ ] | n/a | [ ] | [ ] | [ ] |
| routeExposureMaxRps (1-50) | n/a | [ ] | [ ] | [ ] | [ ] | [ ] |
| routeExposureWorkers (1-16) | n/a | [ ] | [ ] | [ ] | [ ] | [ ] |
| routeExposureTimeout (2-60) | n/a | [ ] | [ ] | [ ] | [ ] | [ ] |
| routeExposureMaxRoutesPerHost (10-5000) | n/a | [ ] | [ ] | [ ] | [ ] | [ ] |
| routeExposureMaxRoutesTotal (50-50000) | n/a | [ ] | [ ] | [ ] | [ ] | [ ] |

## Section and views

- [ ] Body only when enabled; Active badge; NodeInfoTooltip text; Run partial recon only in edit mode with the module on
- [ ] Authentication hint opens Target & Modules
- [ ] Advanced holds the five numeric fields
- [ ] Workflow view: RouteExposure node in group 6, Active badge, BaseURL/Endpoint in, Vulnerability/Endpoint out; click opens the section; Play opens the partial modal
- [ ] Graph page after S1: route_exposure Vulnerability nodes; the /xss-snippet drawer shows escaped text and no dialog opens; an Endpoint drawer shows anon_status
- [ ] Priority Board: leads at T4 / info, findings scored with their class
- [ ] Reports: findings labelled "Route Exposure", no pending lead
- [ ] Red Zone > Route Exposure: unseen badge, every row, pending badged, filters, text filter, /xss-snippet escaped, row mute and unmute, every export format, empty state on a project without the module, loading state on a slow network
- [ ] 390 px wide: section, partial modal and Red Zone table usable, no horizontal overflow

## Partial recon (P1-P7)

- [ ] P1 graph targets, no URL  - [ ] P2 typed URL, Generic  - [ ] P3 typed URL attached to the BaseURL
- [ ] P4 graph off, no URL: Run disabled  - [ ] P5 no BaseURL: no-targets warning
- [ ] P6 outsider URL dropped, 0 hits  - [ ] P7 workflow node and section button give the same nodes
