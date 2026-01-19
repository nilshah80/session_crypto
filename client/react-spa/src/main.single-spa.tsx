import React from 'react';
import ReactDOMClient from 'react-dom/client';
import singleSpaReact from 'single-spa-react';
import App from './App';

const lifecycles = singleSpaReact({
  React,
  ReactDOMClient,
  rootComponent: App,
  errorBoundary(err, _info, _props) {
    return <div>Error: {err.message}</div>;
  },
});

export const { bootstrap, mount, unmount } = lifecycles;
