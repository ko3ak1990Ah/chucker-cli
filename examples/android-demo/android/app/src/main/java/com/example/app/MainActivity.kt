package com.example.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material.icons.filled.ShoppingCart
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.Typography
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

private val AccentBlue = Color(0xFF2563EB)

private val DemoColors = lightColorScheme(
    primary = AccentBlue,
    onPrimary = Color.White,
    background = Color(0xFFF7F9FB),
    surface = Color.White,
)

private val DemoTypography = Typography(
    titleLarge = TextStyle(fontSize = 26.sp, fontWeight = FontWeight.Bold),
    titleMedium = TextStyle(fontSize = 22.sp, fontWeight = FontWeight.SemiBold),
    bodyLarge = TextStyle(fontSize = 20.sp),
    labelLarge = TextStyle(fontSize = 18.sp, fontWeight = FontWeight.SemiBold),
)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val api = ApiClient(applicationContext)
        val products = ProductRepository(api)
        val basket = BasketRepository(api)
        val profiles = ProfileRepository(api)
        setContent {
            MaterialTheme(colorScheme = DemoColors, typography = DemoTypography) {
                DemoShopApp(products, basket, profiles)
            }
        }
    }
}

@Composable
private fun DemoShopApp(
    productRepository: ProductRepository,
    basketRepository: BasketRepository,
    profileRepository: ProfileRepository,
) {
    var showProfile by remember { mutableStateOf(false) }
    var basketCount by remember { mutableIntStateOf(0) }
    var products by remember { mutableStateOf<List<Product>?>(null) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(Unit) {
        products = runCatching { productRepository.products() }.getOrDefault(emptyList())
    }
    BackHandler(enabled = showProfile) { showProfile = false }

    Scaffold(
        topBar = {
            DemoTopBar(
                showBack = showProfile,
                basketCount = basketCount,
                onBack = { showProfile = false },
                onProfile = { showProfile = true },
            )
        },
        containerColor = MaterialTheme.colorScheme.background,
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            if (showProfile) {
                ProfileScreen(profileRepository)
            } else {
                ProductList(
                    products = products,
                    onAdd = { product ->
                        scope.launch {
                            runCatching { basketRepository.addToBasket(product.id) }
                                .onSuccess { if (it) basketCount++ }
                        }
                    },
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DemoTopBar(showBack: Boolean, basketCount: Int, onBack: () -> Unit, onProfile: () -> Unit) {
    TopAppBar(
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = AccentBlue,
            titleContentColor = Color.White,
            navigationIconContentColor = Color.White,
            actionIconContentColor = Color.White,
        ),
        navigationIcon = {
            if (showBack) {
                IconButton(onClick = onBack) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                }
            }
        },
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Image(
                    painter = painterResource(R.drawable.ic_launcher),
                    contentDescription = null,
                    modifier = Modifier
                        .size(40.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(Color.White)
                        .padding(3.dp),
                )
                Spacer(Modifier.width(12.dp))
                Text(if (showBack) "Profile" else "Demo Shop")
            }
        },
        actions = {
            if (!showBack) {
                IconButton(onClick = onProfile) {
                    Icon(Icons.Filled.AccountCircle, contentDescription = "Profile", modifier = Modifier.size(30.dp))
                }
            }
            BadgedBox(
                modifier = Modifier.padding(end = 16.dp, start = 8.dp),
                badge = {
                    if (basketCount > 0) {
                        Badge(containerColor = Color(0xFFFF7900), contentColor = Color.White) {
                            Text("$basketCount", fontSize = 14.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                },
            ) {
                Icon(Icons.Filled.ShoppingCart, contentDescription = "Basket", modifier = Modifier.size(30.dp))
            }
        },
    )
}

@Composable
private fun ProductList(products: List<Product>?, onAdd: (Product) -> Unit) {
    if (products == null) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
        return
    }
    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        items(products, key = { it.id }) { product ->
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(product.name, style = MaterialTheme.typography.titleMedium)
                        Text(product.price, style = MaterialTheme.typography.bodyLarge, color = Color(0xFF555555))
                    }
                    Button(onClick = { onAdd(product) }) { Text("Add to basket") }
                }
            }
        }
    }
}

@Composable
private fun ProfileScreen(profileRepository: ProfileRepository) {
    var profile by remember { mutableStateOf<Profile?>(null) }
    LaunchedEffect(Unit) { profile = runCatching { profileRepository.profile() }.getOrNull() }

    val loaded = profile
    if (loaded == null) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
        return
    }
    Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(20.dp)) {
        ProfileField("Name", loaded.name)
        ProfileField("Email", loaded.email)
        ProfileField("Phone", loaded.phone)
    }
}

@Composable
private fun ProfileField(label: String, value: String) {
    Column {
        Text(label, style = MaterialTheme.typography.labelLarge, color = AccentBlue)
        Text(value, style = MaterialTheme.typography.titleMedium)
    }
}
