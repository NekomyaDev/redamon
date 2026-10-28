'use client'

import { useState } from 'react'
import { ChevronDown, DoorOpen, Play } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { RegistryFields } from '../RegistryFields'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface RouteExposureSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
  /** Opens Target & Modules, where the authentication profile is set. */
  onOpenAuth?: () => void
}

/**
 * Route exposure: an active GROUP 6 Phase A scanner. It requests the routes
 * recon found plus the ones it generates, anonymously and logged in, and writes
 * leads for the agent and findings a signature proves.
 */
export function RouteExposureSection({ data, updateField, onRun, onOpenAuth }: RouteExposureSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const enabled = !!data.routeExposureEnabled
  // Read as the agent reads it (get_enabled_builtin_skills): only a truthy value
  // is on, so a project saved before a skill existed shows the alert.
  const builtIn = (data.attackSkillConfig as { builtIn?: Record<string, unknown> } | null)?.builtIn ?? {}
  const skillOn = (id: string) => !!builtIn[id]

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <DoorOpen size={16} />
          Route Exposure
          <NodeInfoTooltip section="RouteExposure" />
          <WikiInfoButton target="RouteExposure" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && enabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              className={styles.runPartialButton}
              title="Run Route Exposure scan"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={enabled}
              onChange={(checked) => updateField('routeExposureEnabled', checked ?? false)}
              aria-label="Enable Route Exposure"
            />
          </div>
          <ChevronDown size={16} className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`} />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Requests the routes recon found, and routes it generates, without credentials, and logged in
            where your authentication profile covers the host. Writes Vulnerability nodes: leads for the
            agent to confirm, and findings a signature proves (exposed .git and .env files, backups, debug
            consoles). Sends GET and HEAD only and never requests logout, delete or reset paths.
          </p>

          {enabled && !skillOn('access_control') && (
            <p className={`${styles.fieldHint} ${styles.fieldHintCaution}`} role="alert">
              <strong>Half a cycle.</strong> Recon writes leads, but nothing confirms them: turn on Access Control in
              AI Agent &gt; Attack Skills.
            </p>
          )}
          {enabled && (!skillOn('path_traversal') || !skillOn('rce')) && (
            <p className={styles.fieldHint}>
              Exposed files and consoles are proven by Path Traversal and RCE.
            </p>
          )}

          {enabled && (
            <>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>What it requests</label>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Seed paths</div>
                    <div className={styles.toggleDescription}>
                      Well-known internal, admin and debug paths at each host and under each API prefix recon
                      saw, at most 60 per host. On by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.routeExposureSeedPaths ?? true}
                    onChange={(c) => updateField('routeExposureSeedPaths', c ?? true)}
                    aria-label="Seed paths"
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Version control and env files</div>
                    <div className={styles.toggleDescription}>
                      .git, .svn, .hg, .env and web.config at each host and under each top-level folder, at most
                      30 per host. These always get a request. On by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.routeExposureVcsFiles ?? true}
                    onChange={(c) => updateField('routeExposureVcsFiles', c ?? true)}
                    aria-label="Version control and env files"
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Backup file variants</div>
                    <div className={styles.toggleDescription}>
                      Backup copies of the server-side files recon found, plus root archives and dumps. Each
                      is read with HEAD and its first kilobyte, never downloaded. On by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.routeExposureBackupFiles ?? true}
                    onChange={(c) => updateField('routeExposureBackupFiles', c ?? true)}
                    aria-label="Backup file variants"
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Older API versions</div>
                    <div className={styles.toggleDescription}>
                      Tries /api/v1/x next to a /api/v2/x route recon found, at most 3 per route. An old version
                      that answers while the new one is locked is a strong lead. On by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.routeExposureVersionVariants ?? true}
                    onChange={(c) => updateField('routeExposureVersionVariants', c ?? true)}
                    aria-label="Older API versions"
                  />
                </div>
              </div>

              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>What it compares</label>
                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Compare with the logged-in answer</div>
                    <div className={styles.toggleDescription}>
                      Requests each route again with your authentication profile, where it covers the host, to
                      tell a personal page from a public one and to find routes that return too much to their
                      own user. On by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.routeExposureCompareLoggedIn ?? true}
                    onChange={(c) => updateField('routeExposureCompareLoggedIn', c ?? true)}
                    aria-label="Compare with the logged-in answer"
                  />
                </div>
                <p className={`${styles.fieldHint} ${styles.fieldHintCaution}`}>
                  Needs an authentication profile: set it in{' '}
                  {onOpenAuth ? (
                    <button
                      type="button"
                      onClick={onOpenAuth}
                      style={{ background: 'none', border: 0, padding: 0, color: 'var(--accent-primary)',
                               fontWeight: 500, cursor: 'pointer' }}
                    >
                      Target &amp; Modules &gt; Authentication
                    </button>
                  ) : (
                    <>Target &amp; Modules &gt; Authentication</>
                  )}
                  . Without one it still finds routes open to anyone.
                </p>
              </div>

              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>What it reads</label>
                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Personal data detection</div>
                    <div className={styles.toggleDescription}>
                      Stores the kinds and counts of personal data in each answer, never the values. On by
                      default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.routeExposurePiiDetection ?? true}
                    onChange={(c) => updateField('routeExposurePiiDetection', c ?? true)}
                    aria-label="Personal data detection"
                  />
                </div>
              </div>
            </>
          )}

          {enabled && (
            <RegistryFields
              keys={['routeExposureMaxRps', 'routeExposureWorkers', 'routeExposureTimeout', 'routeExposureMaxRoutesPerHost', 'routeExposureMaxRoutesTotal']}
              data={data}
              updateField={updateField}
              title="Advanced"
              description="Requests per second, workers, timeout and route budgets. Bounds, defaults and descriptions come from the settings registry, so they are the same ones the API enforces."
            />
          )}
        </div>
      )}
    </div>
  )
}
