# Demo Shop

A tiny Android app and mock GraphQL server for trying the Chucker CLI end to end. The app has
[Chucker](https://github.com/ChuckerTeam/chucker) in its debug build and two planted bugs that the screen
doesn't show but the traffic does. Everything in it is fake: hosts, products and user data.

## Run it

```sh
./server/run.sh                         # mock server on :8080 (stop with ./server/stop.sh)
cd android && ./gradlew installDebug    # needs an emulator or a device, and the Android SDK
adb shell am start -n com.example.app/.MainActivity

export CHUCKER_PACKAGE=com.example.app
chucker doctor
```

The app talks to `api.example.com` and `api-tst.example.com`, but resolves both to `10.0.2.2`, the host
machine as an emulator sees it. Use an emulator, not a physical device.

## The planted bugs

**Sorting.** The acceptance criterion is *products are shown in the order the backend returns them*. The
server returns them cheapest first, but `ShopRepositories.kt` ends with
`return products.sortedBy { it.name } // BUG`, so the screen shows a tidy A-Z list. The screenshot
looks right; `chucker body <id> --select data.products` shows the real order.

**Basket.** `BasketRepository.kt` sends `quantity = 0` (`// BUG: must be 1`). The server answers HTTP 200
with `errors: [{"message": "Variable \"quantity\" must be positive"}]`, the app ignores `errors`, and the
basket badge goes up anyway. `chucker ls --errors` flags it with `error_kind: graphql`.

Fix either one by deleting the `// BUG` code, rebuild, and let the agent verify with the CLI.

## Try the CLI

```sh
chucker ls --since 5m --fields id,method,path,status,graphql
chucker ls --errors --fields id,path,status,error_kind,error_reason
chucker body <id> --select 'errors[0].message'
chucker curl <id>
```
