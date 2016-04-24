
ABTRARY = "abitrary"
SEPARATOR = "/"
COMMA = ","

# result file
result_path = "/home/guochenkai/download/SW/androguard/androguard/csdTesting/apps/result_file"
record_path = "/home/guochenkai/download/SW/androguard/androguard/csdTesting/apps/record_path"
record_dir = "/home/guochenkai/download/SW/androguard/androguard/csdTesting/apps/record_dir"
"""
Sensitive point: sink and source

For detection of callback-vulnerability

example sink:
    {
        "method":"onLocationChanged",
        "params":"Landroid/location/Location; I",           #split by space
        "return":"V"
    }, 
"""
sink = (
    #Activity
     {
        "class": "android.content.ContextWrapper",
        "method":"startActivity",
        "params":ABTRARY,
        "return":ABTRARY
     },
     
     {
        "class": ABTRARY,
        "method":"setText",
        "params":ABTRARY,
        "return":ABTRARY         
     },  
     
     #Dialog
     {
        "class": "android.app.Dialog",
        #"method":"show",
        "method":"Landroid/app/AlertDialog;->show()",
        "params":ABTRARY,
        "return":ABTRARY          
     },
     
     #Toast
     {
        "class": "android.widget.Toast",
        #"method":"show",
        "method":"Landroid/widget/Toast;->show()",
        "params":ABTRARY,
        "return":ABTRARY          
     },  
     
     #sendBroadcast
     {
        "class": "android.content.ContextWrapper",
        #"method":"sendBroadcast",
        "method":"Lcom/example/servicesink/Servicewithsink;->sendBroadcast",
        "params":ABTRARY,
        "return":ABTRARY          
     }, 
     
     #NotificationManager
     {
        "class": "android.app.NotificationManager",
        #"method":"notify",
        "method":"Landroid/app/NotificationManager;->notify",
        "params":ABTRARY,
        "return":ABTRARY          
     },  
     
     #AudioManager
    #{
       #"class": "AudioManager",
       #"method":"",
       #"params":ABTRARY,
       #"return":ABTRARY          
    #},         
)

# serviceManger events
source = (
    {
            "class": ABTRARY,
            "method":ABTRARY, #no source, completely traverse
            "params":ABTRARY,
            "return":ABTRARY
        },    
    #{
        #"class": ABTRARY,
        #"method":"onLocationChanged",
        #"params":ABTRARY,
        #"return":ABTRARY
    #},
    #{
        #"class": ABTRARY,
        #"method":"onSensorChanged",
        #"params":ABTRARY,
        #"return":ABTRARY
    #}, 
    #{
        #"class": ABTRARY,
        #"method":"onAccuracyChanged",
        #"params":ABTRARY,
        #"return":ABTRARY
    #},
    #{
        #"class": ABTRARY,
        #"method":"onCreate",
        #"params":ABTRARY,
        #"return":ABTRARY
    #} ,
    #{
        #"class": ABTRARY,
        #"method":"run", # inner class only can back-trace to run function
        #"params":ABTRARY,
        #"return":ABTRARY
    #} 
)

first_state_class =[
"Service",
"LaunchActivity",
"BroadcastReceiver",
"$", #inner class
]

system_events_21 = (
"android.app.action.ACTION_PASSWORD_CHANGED",
"android.app.action.ACTION_PASSWORD_EXPIRING",
"android.app.action.ACTION_PASSWORD_FAILED",
"android.app.action.ACTION_PASSWORD_SUCCEEDED",
"android.app.action.DEVICE_ADMIN_DISABLED",
"android.app.action.DEVICE_ADMIN_DISABLE_REQUESTED",
"android.app.action.DEVICE_ADMIN_ENABLED",
"android.app.action.LOCK_TASK_ENTERING",
"android.app.action.LOCK_TASK_EXITING",
"android.app.action.NEXT_ALARM_CLOCK_CHANGED",
"android.app.action.PROFILE_PROVISIONING_COMPLETE",
"android.bluetooth.a2dp.profile.action.CONNECTION_STATE_CHANGED",
"android.bluetooth.a2dp.profile.action.PLAYING_STATE_CHANGED",
"android.bluetooth.adapter.action.CONNECTION_STATE_CHANGED",
"android.bluetooth.adapter.action.DISCOVERY_FINISHED",
"android.bluetooth.adapter.action.DISCOVERY_STARTED",
"android.bluetooth.adapter.action.LOCAL_NAME_CHANGED",
"android.bluetooth.adapter.action.SCAN_MODE_CHANGED",
"android.bluetooth.adapter.action.STATE_CHANGED",
"android.bluetooth.device.action.ACL_CONNECTED",
"android.bluetooth.device.action.ACL_DISCONNECTED",
"android.bluetooth.device.action.ACL_DISCONNECT_REQUESTED",
"android.bluetooth.device.action.BOND_STATE_CHANGED",
"android.bluetooth.device.action.CLASS_CHANGED",
"android.bluetooth.device.action.FOUND",
"android.bluetooth.device.action.NAME_CHANGED",
"android.bluetooth.device.action.PAIRING_REQUEST",
"android.bluetooth.device.action.UUID",
"android.bluetooth.devicepicker.action.DEVICE_SELECTED",
"android.bluetooth.devicepicker.action.LAUNCH",
"android.bluetooth.headset.action.VENDOR_SPECIFIC_HEADSET_EVENT",
"android.bluetooth.headset.profile.action.AUDIO_STATE_CHANGED",
"android.bluetooth.headset.profile.action.CONNECTION_STATE_CHANGED",
"android.bluetooth.input.profile.action.CONNECTION_STATE_CHANGED",
"android.bluetooth.pan.profile.action.CONNECTION_STATE_CHANGED",
"android.hardware.action.NEW_PICTURE",
"android.hardware.action.NEW_VIDEO",
"android.hardware.hdmi.action.OSD_MESSAGE",
"android.hardware.input.action.QUERY_KEYBOARD_LAYOUTS",
"android.intent.action.ACTION_POWER_CONNECTED",
"android.intent.action.ACTION_POWER_DISCONNECTED",
"android.intent.action.ACTION_SHUTDOWN",
"android.intent.action.AIRPLANE_MODE",
"android.intent.action.APPLICATION_RESTRICTIONS_CHANGED",
"android.intent.action.BATTERY_CHANGED",
"android.intent.action.BATTERY_LOW",
"android.intent.action.BATTERY_OKAY",
"android.intent.action.BOOT_COMPLETED",
"android.intent.action.CAMERA_BUTTON",
"android.intent.action.CONFIGURATION_CHANGED",
"android.intent.action.CONTENT_CHANGED",
"android.intent.action.DATA_SMS_RECEIVED",
"android.intent.action.DATE_CHANGED",
"android.intent.action.DEVICE_STORAGE_LOW",
"android.intent.action.DEVICE_STORAGE_OK",
"android.intent.action.DOCK_EVENT",
"android.intent.action.DOWNLOAD_COMPLETE",
"android.intent.action.DOWNLOAD_NOTIFICATION_CLICKED",
"android.intent.action.DREAMING_STARTED",
"android.intent.action.DREAMING_STOPPED",
"android.intent.action.EXTERNAL_APPLICATIONS_AVAILABLE",
"android.intent.action.EXTERNAL_APPLICATIONS_UNAVAILABLE",
"android.intent.action.FETCH_VOICEMAIL",
"android.intent.action.GTALK_CONNECTED",
"android.intent.action.GTALK_DISCONNECTED",
"android.intent.action.HEADSET_PLUG",
"android.intent.action.HEADSET_PLUG",
"android.intent.action.INPUT_METHOD_CHANGED",
"android.intent.action.LOCALE_CHANGED",
"android.intent.action.MANAGE_PACKAGE_STORAGE",
"android.intent.action.MEDIA_BAD_REMOVAL",
"android.intent.action.MEDIA_BUTTON",
"android.intent.action.MEDIA_CHECKING",
"android.intent.action.MEDIA_EJECT",
"android.intent.action.MEDIA_MOUNTED",
"android.intent.action.MEDIA_NOFS",
"android.intent.action.MEDIA_REMOVED",
"android.intent.action.MEDIA_SCANNER_FINISHED",
"android.intent.action.MEDIA_SCANNER_SCAN_FILE",
"android.intent.action.MEDIA_SCANNER_STARTED",
"android.intent.action.MEDIA_SHARED",
"android.intent.action.MEDIA_UNMOUNTABLE",
"android.intent.action.MEDIA_UNMOUNTED",
"android.intent.action.MY_PACKAGE_REPLACED",
"android.intent.action.NEW_OUTGOING_CALL",
"android.intent.action.NEW_VOICEMAIL",
"android.intent.action.PACKAGE_ADDED",
"android.intent.action.PACKAGE_CHANGED",
"android.intent.action.PACKAGE_DATA_CLEARED",
"android.intent.action.PACKAGE_FIRST_LAUNCH",
"android.intent.action.PACKAGE_FULLY_REMOVED",
"android.intent.action.PACKAGE_INSTALL",
"android.intent.action.PACKAGE_NEEDS_VERIFICATION",
"android.intent.action.PACKAGE_REMOVED",
"android.intent.action.PACKAGE_REPLACED",
"android.intent.action.PACKAGE_RESTARTED",
"android.intent.action.PACKAGE_VERIFIED",
"android.intent.action.PHONE_STATE",
"android.intent.action.PROVIDER_CHANGED",
"android.intent.action.PROXY_CHANGE",
"android.intent.action.REBOOT",
"android.intent.action.SCREEN_OFF",
"android.intent.action.SCREEN_ON",
"android.intent.action.TIMEZONE_CHANGED",
"android.intent.action.TIME_SET",
"android.intent.action.TIME_TICK",
"android.intent.action.UID_REMOVED",
"android.intent.action.USER_PRESENT",
"android.intent.action.WALLPAPER_CHANGED",
"android.media.ACTION_SCO_AUDIO_STATE_UPDATED",
"android.media.AUDIO_BECOMING_NOISY",
"android.media.RINGER_MODE_CHANGED",
"android.media.SCO_AUDIO_STATE_CHANGED",
"android.media.VIBRATE_SETTING_CHANGED",
"android.media.action.CLOSE_AUDIO_EFFECT_CONTROL_SESSION",
"android.media.action.HDMI_AUDIO_PLUG",
"android.media.action.OPEN_AUDIO_EFFECT_CONTROL_SESSION",
"android.net.conn.BACKGROUND_DATA_SETTING_CHANGED",
"android.net.conn.CONNECTIVITY_CHANGE",
"android.net.nsd.STATE_CHANGED",
"android.net.scoring.SCORER_CHANGED",
"android.net.scoring.SCORE_NETWORKS",
"android.net.wifi.NETWORK_IDS_CHANGED",
"android.net.wifi.RSSI_CHANGED",
"android.net.wifi.SCAN_RESULTS",
"android.net.wifi.STATE_CHANGE",
"android.net.wifi.WIFI_STATE_CHANGED",
"android.net.wifi.p2p.CONNECTION_STATE_CHANGE",
"android.net.wifi.p2p.DISCOVERY_STATE_CHANGE",
"android.net.wifi.p2p.PEERS_CHANGED",
"android.net.wifi.p2p.STATE_CHANGED",
"android.net.wifi.p2p.THIS_DEVICE_CHANGED",
"android.net.wifi.supplicant.CONNECTION_CHANGE",
"android.net.wifi.supplicant.STATE_CHANGE",
"android.nfc.action.ADAPTER_STATE_CHANGED",
"android.os.action.POWER_SAVE_MODE_CHANGED",
"android.provider.Telephony.SIM_FULL",
"android.provider.Telephony.SMS_CB_RECEIVED",
"android.provider.Telephony.SMS_DELIVER",
"android.provider.Telephony.SMS_EMERGENCY_CB_RECEIVED",
"android.provider.Telephony.SMS_RECEIVED",
"android.provider.Telephony.SMS_REJECTED",
"android.provider.Telephony.SMS_SERVICE_CATEGORY_PROGRAM_DATA_RECEIVED",
"android.provider.Telephony.WAP_PUSH_DELIVER",
"android.provider.Telephony.WAP_PUSH_RECEIVED",
"android.speech.tts.TTS_QUEUE_PROCESSING_COMPLETED",
"android.speech.tts.engine.TTS_DATA_INSTALLED"	
)

"""
whitelist
For improving backtrace efficiency by avoiding tracing specific package, class or method

example item:
    {
        "package":"Lbucik/gps/satellite/signal/checker",    #donnot end by separator
        "class":"Gps8Activity$MyLocationListener;",         # need to end by semicolon
        "method":"onLocationChanged",
        "params":"Landroid/location/Location; I",           #split by space
        "return":"V"
    }, 
"""
whitelist = (
    {
        "package":"Lcom/google/ads",
        "class":ABTRARY,
        "method":ABTRARY,
        "params":ABTRARY,
        "return":ABTRARY
        
    },
    {
        "package":"Landroid/support/v4",
        "class":ABTRARY,
        "method":ABTRARY,
        "params":ABTRARY,
        "return":ABTRARY
    },
    {
        "package":"Lbucik/gps/satellite/signal/checker",
        "class":"Gps8Activity$MyLocationListener;",
        "method":"onLocationChanged",
        "params":"Landroid/location/Location; I",
        "return":"V"
    },     
)

"""
following methods can not be observed as a condition block
"""
unobslist_file = "/home/guochenkai/download/android_permission_api_mappings/mapping_4.1.1.csv"

"""
following methods can not be observed as a member of method_trace
"""
unobs_for_method = (
    # Activity lifecycle method
    {
        "class":"Activity",
        "method":"onPause",
        "params":"",
        "return":"V"
    },
    {
        "class":"Activity",
        "method":"onStop",
        "params":"",
        "return":"V"        
    },
    {
        "class":"Activity",
        "method":"onRestart",
        "params":"",
        "return":"V"        
    },  
    
    # Service lifecycle method
    {
        "class":"Service",
        "method":"onBind",
        "params":"Intent",
        "return":"IBinder"         
    },
    {
        "class":"Service",
        "method":"onUnbind",
        "params":ABTRARY,
        "return":ABTRARY        
    }, 
    
    # callback of View event
    {
        "class":"Landroid/view/View$OnApplyWindowInsetsListener",
        "method":"onApplyWindowInsets",
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter
    },  
    {
        "class":"Landroid/view/View$OnAttachStateChangeListener",
        "method":"onViewAttachedToWindow",
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter
    },  
    {
        "class":"OnAttachStateChangeListener",
        "method":"onViewDetachedFromWindow",
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter
    },         
    {
        "class":"OnClickListener",
        "method":ABTRARY,
        "params":ABTRARY,
        "return":ABTRARY 
    },
    {
        "class":"OnContextClickListener",
        "method":ABTRARY,
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter
    },  
    {
        "class":"Landroid/view/View$OnCreateContextMenuListener",
        "method":"onCreateContextMenu",
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter
    },  
    {
        "class":"Landroid/view/View$OnDragListener",
        "method":"onDrag",
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter
    },  
    {
        "class":"Landroid/view/View$OnFocusChangeListener",
        "method":"onFocusChange",
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter
    },  
    {
        "class":"Landroid/view/View$OnGenericMotionListener",
        "method":"onGenericMotion",
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter
    },  
    {
        "class":"Landroid/view/View$OnHoverListener",
        "method":"onHover",
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter
    },  
    {
        "class":"Landroid/view/View$OnKeyListener",
        "method":"onKey",
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter
    },  
    {
        "class":"Landroid/view/View$OnLayoutChangeListener",
        "method":"onLayoutChange",
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter
    },   
    {
        "class":"Landroid/view/ActionMode$Callback",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/ActionProvider$VisibilityListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/Choreographer$FrameCallback",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/CollapsibleActionView",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/GestureDetector$OnContextClickListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/GestureDetector$OnDoubleTapListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/GestureDetector$OnGestureListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/InputQueue$Callback",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/KeyEvent$Callback",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/MenuItem$OnActionExpandListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/MenuItem$OnMenuItemClickListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/ScaleGestureDetector$OnScaleGestureListene",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/SurfaceHolder$Callback",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/SurfaceHolder$Callback2",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/TextureView$SurfaceTextureListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/ViewGroup$OnHierarchyChangeListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/ViewStub$OnInflateListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/ViewTreeObserver$OnDrawListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/ViewTreeObserver$OnGlobalFocusChangeListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/ViewTreeObserver$OnGlobalLayoutListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/ViewTreeObserver$OnPreDrawListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/ViewTreeObserver$OnScrollChangedListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/ViewTreeObserver$OnTouchModeChangeListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/ViewTreeObserver$OnWindowAttachListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/ViewTreeObserver$OnWindowFocusChangeListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },   
    {
        "class":"Landroid/view/Window$Callback",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },
    
    # callback of event observed with Permission request
    #{
        #"class":ABTRARY,
        #"method":"onLocationChanged", # no matter
        #"params":ABTRARY, # no matter
        #"return":ABTRARY  # no matter        
    #}, 
    #{
        #"class":ABTRARY,
        #"method":"onProviderDisabled", # no matter
        #"params":ABTRARY, # no matter
        #"return":ABTRARY  # no matter        
    #},  
    #{
        #"class":ABTRARY,
        #"method":"onProviderEnabled", # no matter
        #"params":ABTRARY, # no matter
        #"return":ABTRARY  # no matter        
    #},     
    #{
        #"class":ABTRARY,
        #"method":"onStatusChanged", # no matter
        #"params":ABTRARY, # no matter
        #"return":ABTRARY  # no matter        
    #},  
    {
        "class":"Landroid/net/wifi/p2p/WifiP2pManager$ChannelListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },  
    {
        "class":"Landroid/net/wifi/WifiManager$ChannelListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },    
    {
        "class":"Landroid/telephony/PhoneStateListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },     
    {
        "class":"Landroid/location/LocationListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },     
    {
        "class":"Landroid/accounts/OnAccountsUpdateListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },     
    {
        "class":"Landroid/location/GpsStatus$NmeaListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },     
    {
        "class":"Landroid/location/GpsStatus$Listener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },     
    {
        "class":"Landroid/net/sip/SipAudioCall$Listener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },     
    {
        "class":"Landroid/net/sip/SipRegistrationListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },     
    {
        "class":"Landroid/net/sip/SipSession$Listener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },     
    {
        "class":"Landroid/speech/RecognitionListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    }, 
    {
        "class":"Landroid/inputmethodservice/KeyboardView",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },     
    
    # Dialog
    
    {
        "class":"DialogInterface$OnDismissListener",
        "method":ABTRARY, # no matter
        "params":ABTRARY, # no matter
        "return":ABTRARY  # no matter        
    },    
    
)
