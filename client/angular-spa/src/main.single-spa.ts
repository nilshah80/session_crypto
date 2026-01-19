import { enableProdMode, NgZone } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { singleSpaAngular, getSingleSpaExtraProviders } from 'single-spa-angular';
import { AppComponent } from './app/app.component';
import { appConfig } from './app/app.config';

// For production mode
// enableProdMode();

const lifecycles = singleSpaAngular({
  bootstrapFunction: (singleSpaProps) => {
    return bootstrapApplication(AppComponent, {
      providers: [
        ...appConfig.providers,
        getSingleSpaExtraProviders()
      ]
    });
  },
  template: '<app-root />',
  NgZone
});

export const bootstrap = lifecycles.bootstrap;
export const mount = lifecycles.mount;
export const unmount = lifecycles.unmount;
