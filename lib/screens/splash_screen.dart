import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:local_auth/local_auth.dart';
import 'package:provider/provider.dart';

import '../agent/agent_controller.dart';
import '../ai_brain.dart';
import '../network_auditor.dart';
import '../providers/aura_state_provider.dart';
import '../secure_vault.dart';
import '../theme/aura_tokens.dart';
import 'aura_core_screen.dart';

class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen>
    with SingleTickerProviderStateMixin {
  late final AnimationController _animationController;
  final LocalAuthentication _auth = LocalAuthentication();
  late final AuraSecureVault _secureVault;
  late final AuraAIBrain _aiBrain;
  double _loadingProgress = 0;
  String _bootStatusText = 'INICIALIZANDO BÓVEDA SEGURA...';
  bool _isAuthFailed = false;
  bool _isAuthenticating = false;

  @override
  void initState() {
    super.initState();
    AuraAIBrain.onModelIntegrityFailure = (message) {
      AgentController.instance.reportCriticalError(message);
    };
    _secureVault = AuraSecureVault();
    _aiBrain = AuraAIBrain(secureVault: _secureVault);
    _animationController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1800),
    )..repeat(reverse: true);
    unawaited(_initializeSystem());
  }

  @override
  void dispose() {
    _animationController.dispose();
    super.dispose();
  }

  Future<void> _initializeSystem() async {
    setState(() {
      _isAuthFailed = false;
      _loadingProgress = 0;
      _bootStatusText = 'VERIFICANDO HARDWARE DE HUELLA...';
    });
    await _authenticateUser();
  }

  Future<void> _authenticateUser() async {
    if (_isAuthenticating) return;
    setState(() {
      _isAuthenticating = true;
      _isAuthFailed = false;
      _bootStatusText = 'VERIFICANDO HARDWARE DE HUELLA...';
    });

    try {
      final canCheckBiometrics = await _auth.canCheckBiometrics;
      if (!canCheckBiometrics) {
        _showAuthenticationFailure('NO HAY HARDWARE BIOMÉTRICO DISPONIBLE.');
        return;
      }

      final availableBiometrics = await _auth.getAvailableBiometrics();
      if (!availableBiometrics.contains(BiometricType.fingerprint)) {
        _showAuthenticationFailure('NO HAY HUELLA DACTILAR REGISTRADA.');
        return;
      }

      final authenticated =
          await AgentController.instance.authenticateBiometricDevice();
      if (!authenticated) {
        _showAuthenticationFailure('ACCESO DENEGADO - NÚCLEO BLOQUEADO.');
        return;
      }

      if (!mounted) return;
      setState(() {
        _loadingProgress = 0.35;
        _bootStatusText = 'HUELLA VALIDADA; INICIALIZANDO BÓVEDA SEGURA...';
      });
      await _secureVault.getOrCreateModelMasterKey();
      if (!mounted) return;
      setState(() {
        _loadingProgress = 0.55;
        _bootStatusText = 'DESCIFRANDO MODELO AES-256...';
      });
      final modelReady = await _aiBrain.preloadModel();
      if (!mounted) return;
      // The console is authenticated: start listening to native DNS/SNI
      // events so blocked/DGA hosts reach the local forest and the UI.
      AuraNetworkAuditor.ensureStarted(
        secureVault: _secureVault,
        aiBrain: _aiBrain,
      ).attachStateProvider(context.read<AuraStateProvider>());
      setState(() {
        _loadingProgress = 0.85;
        _bootStatusText = modelReady
            ? 'BOSQUE LOCAL VALIDADO: 500 ÁRBOLES.'
            : 'MODELO NO VERIFICADO; REGLAS LOCALES ACTIVAS.';
      });
      await Future<void>.delayed(const Duration(milliseconds: 350));
      if (!mounted) return;
      setState(() {
        _loadingProgress = 1;
        _bootStatusText = 'AURA LISTA; EL TÚNEL VPN REQUIERE CONSENTIMIENTO.';
      });
      await Future<void>.delayed(const Duration(milliseconds: 350));
      _navigateToCore();
    } on PlatformException catch (error) {
      _showAuthenticationFailure(
        'ERROR DE ACCESO BIOMÉTRICO: ${error.message ?? error.code}',
      );
    } on Object catch (error) {
      _showAuthenticationFailure('ERROR DE INICIALIZACIÓN: $error');
    } finally {
      if (mounted) setState(() => _isAuthenticating = false);
    }
  }

  void _showAuthenticationFailure(String message) {
    if (!mounted) return;
    setState(() {
      _isAuthFailed = true;
      _bootStatusText = message;
    });
    AgentController.instance.reportCriticalError('PÁNICO CRÍTICO: $message');
    unawaited(
      Future<void>.delayed(const Duration(seconds: 2)).then((_) async {
        if (mounted) await SystemNavigator.pop();
      }),
    );
  }

  void _navigateToCore() {
    if (!mounted) return;
    Navigator.of(context).pushReplacement(
      PageRouteBuilder<void>(
        pageBuilder: (context, animation, secondaryAnimation) =>
            const AuraCoreScreen(),
        transitionsBuilder: (context, animation, secondaryAnimation, child) =>
            FadeTransition(
          opacity: CurvedAnimation(
            parent: animation,
            curve: Curves.fastOutSlowIn,
          ),
          child: child,
        ),
        transitionDuration: const Duration(milliseconds: 600),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AuraTokens.bg,
      body: Stack(
        children: [
          Positioned.fill(
            child: Opacity(
              opacity: 0.035,
              child: GridPaper(
                color: AuraTokens.accent,
                interval: 30,
                divisions: 1,
                subdivisions: 1,
              ),
            ),
          ),
          SafeArea(
            child: Center(
              child: Padding(
                padding: const EdgeInsets.all(AuraTokens.s4),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    AnimatedBuilder(
                      animation: _animationController,
                      builder: (context, child) {
                        final pulse = _animationController.value;
                        return Container(
                          width: 130,
                          height: 130,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            border: Border.all(
                              color: (_isAuthFailed
                                      ? AuraTokens.danger
                                      : AuraTokens.accent)
                                  .withValues(
                                alpha: 0.2 + pulse * 0.3,
                              ),
                              width: 1.5,
                            ),
                            boxShadow: [
                              BoxShadow(
                                color: (_isAuthFailed
                                        ? AuraTokens.danger
                                        : AuraTokens.accent)
                                    .withValues(
                                  alpha: 0.1 + pulse * 0.25,
                                ),
                                blurRadius: 40 + pulse * 25,
                                spreadRadius: 2 + pulse * 6,
                              ),
                            ],
                          ),
                          child: Center(
                            child: Icon(
                              Icons.shield_moon_rounded,
                              size: 72,
                              color: (_isAuthFailed
                                      ? AuraTokens.danger
                                      : AuraTokens.accent)
                                  .withValues(
                                alpha: 0.7 + pulse * 0.3,
                              ),
                            ),
                          ),
                        );
                      },
                    ),
                    const SizedBox(height: AuraTokens.s8),
                    const Text(
                      'AURA',
                      style: TextStyle(
                        color: AuraTokens.textPrimary,
                        fontSize: 38,
                        fontWeight: FontWeight.w200,
                        fontFamily: 'monospace',
                      ),
                    ),
                    const SizedBox(height: AuraTokens.s1),
                    const Text(
                      'SOVEREIGN MOBILE DEFENSE',
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        color: AuraTokens.textMuted,
                        fontSize: 10,
                        fontWeight: FontWeight.w400,
                      ),
                    ),
                    const SizedBox(height: AuraTokens.s8),
                    SizedBox(
                      width: 220,
                      child: Column(
                        children: [
                          LinearProgressIndicator(
                            value: _loadingProgress,
                            minHeight: 2,
                            backgroundColor: AuraTokens.surfaceAlt,
                            valueColor: AlwaysStoppedAnimation<Color>(
                              _isAuthFailed
                                  ? AuraTokens.danger
                                  : AuraTokens.accent,
                            ),
                          ),
                          const SizedBox(height: AuraTokens.s3),
                          Text(
                            _bootStatusText,
                            textAlign: TextAlign.center,
                            style: TextStyle(
                              color: _isAuthFailed
                                  ? AuraTokens.danger
                                  : AuraTokens.accent,
                              fontSize: 10,
                              fontFamily: 'monospace',
                            ),
                          ),
                          if (_isAuthFailed && !_isAuthenticating) ...[
                            const SizedBox(height: AuraTokens.s2),
                            IconButton(
                              tooltip: 'Reintentar autenticación biométrica',
                              onPressed: _initializeSystem,
                              icon: const Icon(
                                Icons.refresh,
                                color: AuraTokens.warning,
                              ),
                            ),
                          ],
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
