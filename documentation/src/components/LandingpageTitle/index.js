import React from 'react';
import clsx from 'clsx';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext'
import useBaseUrl from '@docusaurus/useBaseUrl'
import styles from './styles.module.css';


function LandingpageTitle() {
  const { siteConfig } = useDocusaurusContext();

  return (
    <div className={clsx(styles.heading)}>
      <img className={clsx(styles.headingImage)} src={useBaseUrl('/img/libraries.png')} />
      <div>
        <h1 className={clsx(styles.headingTitle)}>{siteConfig.title}</h1>
        <span className={clsx('grey', 'section-header')}>{siteConfig.tagline}</span>
      </div>
    </div>
  )
}

export default LandingpageTitle
