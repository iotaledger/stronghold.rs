import React from 'react'
import clsx from 'clsx'
import LandingpageActions from '../LandingpageActions'
import LandingpageTitle from '../LandingpageTitle'
import styles from './styles.module.css'

function LandingpageHeader() {
  return (
    <header className={clsx('padding-top--xl', styles.header)}>
      <LandingpageTitle />
      <LandingpageActions />
    </header>
  )
}

export default LandingpageHeader