## What is Semver?
[Semver](http://semver.org) is a scheme for meaningful versioning that aims to eliminate "dependency hell." To quote the author:
> If dependency specifications are too tight, you are in danger of version lock (the inability to upgrade a package without having to release new versions of every dependent package). If dependencies are specified too loosely, you will inevitably be bitten by version promiscuity (assuming compatibility with more future versions than is reasonable). Dependency hell is where you are when version lock and/or version promiscuity prevents you from easily and safely moving your project forward.

By defining what constitues a major, minor, or patch update, Semver applies uniformity to versioning. If this standard is applied ubiquitously across an organization, it becomes easier for teams to understand what kinds of changes may be needed to continue using a recently updated dependency as indicated by its version bump.

## How does this compare to the current system?
Most developers are currently not in the habit of using module and service versions as a meaningful metric and instead opt to relying on the CI/CD pipeline to differentiate each commit build. This system indaverdently allows versions to be ignored due to the nature of how auto increments are implemented. It does not matter if the version is bumped since each build is automatically appended with a build number and commit hash, effectively producing a unique version. Unfortunatley, any information the version is meant to convey is lost. With this scheme, there is no way to compare two versions and intuitively estimate how much has changed between each.

Currently:
* Versions are used as a simple fingerprint instead of a meaningful indicator of change.
* A consumer cannot specify how much variability they are willing to tolerate in the modules they use.
* The current version scheme of major.minor.patch-build-hash prevents prevents the use of version ranges due to how npm treats version schemes. (This is explored in more detail.)

## How does NPM handle versions?

A quick summary:
* Versions are formatted as `major.minor.patch` with some caveats for prereleases.
* Patch releases: `1.0` or `1.0.x` or `~1.0.4`
* Minor releases: `1` or `1.x` or `^1.0.4`
* Major releases: `*` or `x`

It also supports more [granular ranges](https://docs.npmjs.com/misc/semver). What is relevant to our setup is how a prerelease series is handled. A **prerelease series** is a set of versions that the author deems unstable for public use. It is known that there will be rapid changes and the user accepts any breaking behavior that may be introduced. They are indicated by **prerelease tags** which are defined as any text after the first `-` succeeding `patch` and before the first `.` afterward. For example, for the version `1.2.3-beta.0`, `beta` is the prerelease tag indicating the `beta` prerelease series, and `0` is the version of that prerelease series.

### How does the current system behave under these rules?
The CI/CD pipeline produces versions with the scheme as `major.minor.patch-build-commit` on every build. Under Semver, all these resultant versions are considered unique prerelease series. This has implications when using ranges.

**[Tilde Ranges](https://docs.npmjs.com/misc/semver#tilde-ranges-123-12-1) (Prereleases)**
> `~1.2.3-beta.2` := `>=1.2.3-beta.2 <1.3.0` Note that prereleases in the 1.2.3 version will be allowed, if they are greater than or equal to beta.2. So, 1.2.3-beta.4 would be allowed, but 1.2.4-beta.2 would not, because it is a prerelease of a different [major, minor, patch] tuple.

This range restricts versions in the same prerelease series for any prerelease version that is greater than or equal to the currently selected prerelease version. In our current version scheme, we techinically do not use prerelease versions as each build is effectively it's own prerelease series containing one version. Because of this, **tilde ranges currently cannot be used**

**[Carat Ranges](https://docs.npmjs.com/misc/semver#caret-ranges-123-025-004) (Prereleases)**
>`^0.0.3-beta` := `>=0.0.3-beta <0.0.4` Note that prereleases in the 0.0.3 version only will be allowed, if they are greater than or equal to beta. So, 0.0.3-pr.2 would be allowed.

This range restricts versions to any prerelease series that is lexocographically greater than or equal to the current prerelease series for the given `major.minor.patch`. In the current versioning scheme, all versions are unique prereleases beginning with an auto-incremented build number. Each build for the same `major.minor.patch` is therefore lexocographically greater than the previous build, which translates this range to "Give me the last build for this version number." This may not be intended behavior.

## What qualifies as a major, minor, or patch version update?

The Semver specification provides more clarity on specifics, but we can summarize the most common patch updates through examples.
>**Note:** these examples are laid out in npm's semantic versioning [overview video](https://youtu.be/kK4Meix58R4)

Let's asusme we are the authors of a module `example@1.0.0` that originally exposed the following function:

```js
function() {
  console.log("This message is from the npm-demo-pkg module".read);
}
```
### Patch
Some of our users have complained that the function is not behaving correctly and we realize that `read` should be `red`. We issue a change:
```js
function() {
  console.log*"This message is from the npm-demo-pkg module".red);
}
```
This change fixes a bug, does not add any new functionality, and did not break any previous APIs. It is therefore a **patch upate**. We version bump with `npm version patch`, which results in version `example@1.0.1`, and publish our module.

### Minor
Our module has become wildly successful and we want to improve on its success. We want to give our users the option to specify the color so we issue another change:

```js
function(color) {
  if(!color) {
    color = `red`;
  }
  console.log("This message is from the npm-demo-pkg module"[color]);
}
```
This change adds new functionality that is backwards compatible. If they chose to, users are given the option to utilize the new functionality, but no requirements are imposed. No change is necessary for current users, which makes this a **minor update**. We version bump with `npm version minor`, which results in version `example@1.1.1`, and publish our module.

### Major
Time has passed, experience was gained, our startup was acquired, and we realize that we could do much better. Our marketing team has an amazing campaign for our next generation release in which we promise that you can now set the message that is printed. Let's make it happen:

```js
function(color, msg) {
  if(!color) {
    color = `red`;
  }
  console.log*(msg[color]);
}
```

This change adds new functionality, but does so in a non backwards compatible way. Our current users will not be able to use this module without have to change their code. We indicate this type of change with a **major update**. We version bump with `npm version major`, which results in version `example@2.1.1`, and we publish our module.

### FAQ
Semver does a great job answering most common questions in its [FAQ](http://semver.org/#faq)::
>
>**How should I deal with revisions in the 0.y.z initial development phase?**
>
>The simplest thing to do is start your initial development release at 0.1.0 and then increment the minor version for each subsequent release.
>
>**How do I know when to release 1.0.0?**
>
>If your software is being used in production, it should probably already be 1.0.0. If you have a stable API on which users have come to depend, you should be 1.0.0. If youâ€™re worrying a lot about backwards compatibility, you should probably already be 1.0.0.
>
>**Doesnâ€™t this discourage rapid development and fast iteration?**
>
>Major version zero is all about rapid development. If youâ€™re changing the API every day you should either still be in version 0.y.z or on a separate development branch working on the next major version.
>
>**If even the tiniest backwards incompatible changes to the public API require a major version bump, wonâ€™t I end up at version 42.0.0 very rapidly?**
>
>This is a question of responsible development and foresight. Incompatible changes should not be introduced lightly to software that has a lot of dependent code. The cost that must be incurred to upgrade can be significant. Having to bump major versions to release incompatible changes means youâ€™ll think through the impact of your changes, and evaluate the cost/benefit ratio involved.
>
>**Documenting the entire public API is too much work!**
>
>It is your responsibility as a professional developer to properly document software that is intended for use by others. Managing software complexity is a hugely important part of keeping a project efficient, and thatâ€™s hard to do if nobody knows how to use your software, or what methods are safe to call. In the long run, Semantic Versioning, and the insistence on a well defined public API can keep everyone and everything running smoothly.
>
>**What do I do if I accidentally release a backwards incompatible change as a minor version?**
>
>As soon as you realize that youâ€™ve broken the Semantic Versioning spec, fix the problem and release a new minor version that corrects the problem and restores backwards compatibility. Even under this circumstance, it is unacceptable to modify versioned releases. If itâ€™s appropriate, document the offending version and inform your users of the problem so that they are aware of the offending version.
>
>**What should I do if I update my own dependencies without changing the public API?**
>
>That would be considered compatible since it does not affect the public API. Software that explicitly depends on the same dependencies as your package should have their own dependency specifications and the author will notice any conflicts. Determining whether the change is a patch level or minor level modification depends on whether you updated your dependencies in order to fix a bug or introduce new functionality. I would usually expect additional code for the latter instance, in which case itâ€™s obviously a minor level increment.
>
>**What if I inadvertently alter the public API in a way that is not compliant with the version number change (i.e. the code incorrectly introduces a major breaking change in a patch release)**
>
>Use your best judgment. If you have a huge audience that will be drastically impacted by changing the behavior back to what the public API intended, then it may be best to perform a major version release, even though the fix could strictly be considered a patch release. Remember, Semantic Versioning is all about conveying meaning by how the version number changes. If these changes are important to your users, use the version number to inform them.
>
>**How should I handle deprecating functionality?**
>
>Deprecating existing functionality is a normal part of software development and is often required to make forward progress. When you deprecate part of your public API, you should do two things: (1) update your documentation to let users know about the change, (2) issue a new minor release with the deprecation in place. Before you completely remove the functionality in a new major release there should be at least one minor release that contains the deprecation so that users can smoothly transition to the new API.
>
>**Does semver have a size limit on the version string?**
>
>No, but use good judgment. A 255 character version string is probably overkill, for example. Also, specific systems may impose their own limits on the size of the string.

## How are version updates handled?
There are a couple of ways we can chose to handle version bumping. Each needs to be considered before one is chosen as the company standard.
### Manual
It is up to the devloper to manually change the module version before commiting. Jenkins will then act on this version and apply the necessary transformations as indicated by the below flowchart. This allows teams to choose their own release strategies and does not impose any git structure.
### Gitflow
Teams would have to adhere to the [Gitflow](http://nvie.com/posts/a-successful-git-branching-model/) branching model. Jenkins could be hooked into each of the different branches, allowing it to perform different version bumps based on the activity of each branch. This approach advocates for a unfiied release model across teams, but would take away the freedom of each team to choose how they want to implement their source control flows.

## How should Jenkins behave on builds?

Assuming manual versioning is chosen:

* If a version is changed and it **does not** contain an explicit prerelease tag, it is considered a release and is published.
* If a version is changed and it **does** contain an explicit prerelease tag, it is considered another build in the prerelease series.
* If a version is not changed and it **does not** contain a prerelease tag, it is inferred that this build is not ready for release and is considered a prerelease. It will be assigned a unique prerelease tag.
* If a version is not changed it **does** contain a prerelease tag, it is a continuation of a previous prerelease series.
* If a version is a release, it will fail if it has any prerelease modules as dependencies.

> **Note**: This is subject to change based on the chosen release procedure.

![Jenkins manual version flowchart](images/jenkins-manual.png)

### Examples
A build is triggered for a package `example`:

* The current version is set to `1.2.4`. The last build was version `1.2.3`.
  * The version has changed.
  * It does not contain a prerelease tag.
  * Jenkins will interpret this as a new release.
  * The package is published as `example@1.2.4`.
* The current version is set to `1.2.3`. The last build was version `1.2.3`.
  * The version has not changed
  * It does not contain a prerelease tag.
  * Jenkins will interpret this as a prerelease.
  * It assigns the hash for the commit that has triggered the build as the prerelease tag.
  * It assigns the build counter as the prerelease version.
  * Assuming the hash of the commit is `56e05fced` and the build counter is `987`, the package is published as `example@1.2.3-56e05fced.987`.
* The current version is set to `1.2.4-alpha`. The last build was version `1.2.3`.
  * The version has changed.
  * It contains a prerelease tag.
  * Jenkins will interpret this as another build in the prerelease series.
  * Assuming the build counter is `987`, a package is published as `example@1.2.4-alpha.987`.
* The current version is set to `1.2.4-beta`. The last build was version `1.2.4-alpha`.
  * The version has changed.
  * It contains a prerelease tag.
  * Jenkins will interpret this as another build in the prerelease series.
  * Assuming the build counter is `988`, a package is published as `example@1.2.4-beta.988`.

## How does this affect service deployments?
When services are being deployed:
* The last non-prerelease version of that service is chosen for deployment.
* Prerelease service versions are not considered because prereleases by their nature are unstable for use and are intended only for development and testing.
* If a service has not had a release since last deployment, then it will not be redeployed.

## What is required from module authors?
It is critical that developeres resolve to utilizing semantic versioning. This proposal will only work if all developers agree to the standard set forth by Semver. A developer must understand the implications for each release type. A type signals to module users what kind of change they can expect in an update and what may be required from them to continue use. Developers should also discourage the use of prereleases outside of development or testing. If developers get into the habit of sticking to using prereleases, then we will end up at the same position we started with: unclear versioning.

## What is recommended for module users?
* Using carat ranges. This will allow automatic acceptance of updates that either add functionality (minor release), or fix bugs (patch release). If all authors adhere to Semver, then you are guaranteed that neither of these updates will break current use.
* Refusing to use any prerelease versions as dependency when issuing a release, especially for modules not owned by the user's team. Prereleases are not intended for use outside of development and testing. Using them in a release will increase the risk of introducing hard to track bugs.

## Adoption Checklist
1. Create a proposal draft
2. Settle on standards
3. Modify build pipelines as needed
4. Migrate old versions
5. Communicate to teams
6. Enforce agreed upon versioning strategy.
