/**
 * * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.
 */

module.exports = {
  mySidebar: [{
      type: 'doc',
      id: 'welcome',
      label: 'Welcome'
    }, {
      type: 'doc',
      id: 'overview/README',
      label: 'Overview'
    },
    {
      type: 'category',
      label: 'Structure',
      items: [{
          type: 'doc',
          id: 'structure/README',
          label: 'Overview'
        }, {
          type: 'doc',
          id: 'structure/client',
          label: 'Client'
        },
        {
          type: 'category',

          label: 'Engine',
          items: [

            {
              type: 'doc',
              id: 'structure/engine',
              label: 'Overview'
            },

            {
              type: 'doc',
              id: 'structure/snapshot',
              label: 'Snapshot'
            },

            {
              type: 'doc',
              id: 'structure/vault',
              label: 'Vault'
            },

            {
              type: 'doc',
              id: 'structure/store',
              label: 'Store'
            },

            {
              type: 'doc',
              id: 'structure/runtime',
              label: 'Runtime'
            },
          ],
        },
        {
          type: 'doc',
          id: 'structure/p2p',
          label: 'P2P Communication'
        },
        {
          type: 'doc',
          id: 'structure/derive',
          label: 'Derive'
        },
        {
          type: 'doc',
          id: 'structure/utils',
          label: 'Utils'
        },
      ]
    },
    {
      type: 'doc',
      id: 'products/README',
      label: 'Products'
    },
    {
      type: 'category',
      label: 'Specification',
      items: [{
        type: 'doc',
        id: 'specs/README',
        label: 'Overview'
      }, {
        type: 'doc',
        id: 'specs/scope',
        label: 'Scope'
      }, {
        type: 'doc',
        id: 'specs/engineering',
        label: 'Engineering'
      }, ]
    },
    {
      type: 'doc',
      id: 'retrospective/README',
      label: 'Retrospective'
    },
    {
      type: 'doc',
      id: 'contribute',
      label: 'Contribute'
    },
    {
      type: 'link',
      href: 'https://github.com/iotaledger/stronghold.rs',
      label: 'GitHub'
    },

  ]
};