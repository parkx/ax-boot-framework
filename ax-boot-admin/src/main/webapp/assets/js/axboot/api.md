## Members

<dl>
<dt><a href="#axboot">axboot</a> : <code>Object</code></dt>
<dd></dd>
<dt><a href="#axMask">axMask</a></dt>
<dd><p>기본 마스크</p>
</dd>
<dt><a href="#axDialogMask">axDialogMask</a></dt>
<dd><p>다이얼로그용 마스크</p>
</dd>
<dt><a href="#axAJAXMask">axAJAXMask</a></dt>
<dd><p>ajax용 마스크</p>
</dd>
<dt><a href="#axModal">axModal</a></dt>
<dd><p>기본 모달</p>
</dd>
<dt><a href="#axDialog">axDialog</a></dt>
<dd></dd>
<dt><a href="#axWarningDialog">axWarningDialog</a></dt>
<dd></dd>
<dt><a href="#axToast">axToast</a></dt>
<dd></dd>
<dt><a href="#axWarningToast">axWarningToast</a></dt>
<dd></dd>
</dl>

<a name="axboot"></a>

## axboot : <code>Object</code>
**Kind**: global variable  

* [axboot](#axboot) : <code>Object</code>
    * [.def](#axboot.def) : <code>Object</code>
    * [.pageAutoHeight](#axboot.pageAutoHeight) : <code>Object</code>
    * [.call](#axboot.call) : <code>Object</code>
    * [.modal](#axboot.modal) : <code>Object</code>
        * [.open(modalConfig)](#axboot.modal.open)
        * [.css(modalCss)](#axboot.modal.css)
        * [.align(modalAlign)](#axboot.modal.align)
        * [.close()](#axboot.modal.close)
        * [.minimize()](#axboot.modal.minimize)
    * [.preparePlugin](#axboot.preparePlugin) : <code>Object</code>
        * [.define()](#axboot.preparePlugin.define)
        * [.pageStart()](#axboot.preparePlugin.pageStart)
    * [.commonView](#axboot.commonView) : <code>Object</code>
    * [.init()](#axboot.init)
    * [.pageStart()](#axboot.pageStart)
    * [.pageResize()](#axboot.pageResize)
    * [.layoutResize()](#axboot.layoutResize)
    * [.ajax(http, callBack, [options])](#axboot.ajax)
    * [.gridBuilder(_config)](#axboot.gridBuilder)
    * [.extend(_obj1, _obj2)](#axboot.extend)
    * [.actionExtend([_actionThis], _action)](#axboot.actionExtend)

<a name="axboot.def"></a>

### axboot.def : <code>Object</code>
axboot의 환경 변수 저장 공간

**Kind**: static property of <code>[axboot](#axboot)</code>  
**Example**  
```js
<a name="axboot.pageAutoHeight"></a>

### axboot.pageAutoHeight : <code>Object</code>
**Kind**: static property of <code>[axboot](#axboot)</code>  
<a name="axboot.call"></a>

### axboot.call : <code>Object</code>
axboot.call

**Kind**: static property of <code>[axboot](#axboot)</code>  
**Example**  
```js
<a name="axboot.modal"></a>

### axboot.modal : <code>Object</code>
axboot.modal

**Kind**: static property of <code>[axboot](#axboot)</code>  

* [.modal](#axboot.modal) : <code>Object</code>
    * [.open(modalConfig)](#axboot.modal.open)
    * [.css(modalCss)](#axboot.modal.css)
    * [.align(modalAlign)](#axboot.modal.align)
    * [.close()](#axboot.modal.close)
    * [.minimize()](#axboot.modal.minimize)

<a name="axboot.modal.open"></a>

#### modal.open(modalConfig)
지정한 조건으로 ax5 modal을 엽니다. modalConfig 를 넘기지 않으면 지정된 기본값으로 엽니다.

**Kind**: static method of <code>[modal](#axboot.modal)</code>  

| Param | Type |
| --- | --- |
| modalConfig | <code>Object</code> | 
| modalConfig.width | <code>Number</code> | 
| modalConfig.height | <code>Number</code> | 
| modalConfig.position | <code>Object</code> | 
| modalConfig.position.left | <code>String</code> | 
| modalConfig.position.top | <code>String</code> | 
| modalConfig.iframeLoadingMsg | <code>String</code> | 
| modalConfig.iframe.method | <code>String</code> | 
| modalConfig.iframe.url | <code>String</code> | 
| modalConfig.closeToEsc | <code>Boolean</code> | 
| modalConfig.animateTime | <code>Number</code> | 
| modalConfig.zIndex | <code>Number</code> | 
| modalConfig.fullScreen | <code>Boolean</code> | 
| modalConfig.header | <code>Object</code> | 
| modalConfig.header.title | <code>String</code> | 

**Example**  
```js
<a name="axboot.modal.css"></a>

#### modal.css(modalCss)
ax5 modal css 를 적용합니다.

**Kind**: static method of <code>[modal](#axboot.modal)</code>  

| Param |
| --- |
| modalCss | 

<a name="axboot.modal.align"></a>

#### modal.align(modalAlign)
ax5 modal을 정렬합니다.

**Kind**: static method of <code>[modal](#axboot.modal)</code>  

| Param |
| --- |
| modalAlign | 

<a name="axboot.modal.close"></a>

#### modal.close()
ax5 modal을 닫습니다.

**Kind**: static method of <code>[modal](#axboot.modal)</code>  
<a name="axboot.modal.minimize"></a>

#### modal.minimize()
ax5 modal을 최소화 합니다.

**Kind**: static method of <code>[modal](#axboot.modal)</code>  
<a name="axboot.preparePlugin"></a>

### axboot.preparePlugin : <code>Object</code>
axboot.preparePlugin

**Kind**: static property of <code>[axboot](#axboot)</code>  

* [.preparePlugin](#axboot.preparePlugin) : <code>Object</code>
    * [.define()](#axboot.preparePlugin.define)
    * [.pageStart()](#axboot.preparePlugin.pageStart)

<a name="axboot.preparePlugin.define"></a>

#### preparePlugin.define()
js가 실행되는 타임. 페이지 레디 전에 미리 선언 하는 경우

**Kind**: static method of <code>[preparePlugin](#axboot.preparePlugin)</code>  
<a name="axboot.preparePlugin.pageStart"></a>

#### preparePlugin.pageStart()
페이지가 레디된 다음 선언하는 경우.

**Kind**: static method of <code>[preparePlugin](#axboot.preparePlugin)</code>  
<a name="axboot.commonView"></a>

### axboot.commonView : <code>Object</code>
각 뷰에 원형

**Kind**: static property of <code>[axboot](#axboot)</code>  
<a name="axboot.init"></a>

### axboot.init()
**Kind**: static method of <code>[axboot](#axboot)</code>  
<a name="axboot.pageStart"></a>

### axboot.pageStart()
**Kind**: static method of <code>[axboot](#axboot)</code>  
<a name="axboot.pageResize"></a>

### axboot.pageResize()
**Kind**: static method of <code>[axboot](#axboot)</code>  
<a name="axboot.layoutResize"></a>

### axboot.layoutResize()
**Kind**: static method of <code>[axboot](#axboot)</code>  
<a name="axboot.ajax"></a>

### axboot.ajax(http, callBack, [options])
**Kind**: static method of <code>[axboot](#axboot)</code>  

| Param | Type |
| --- | --- |
| http | <code>Object</code> | 
| callBack | <code>function</code> | 
| [options] | <code>Object</code> | 
| [options.onError] | <code>function</code> | 
| [options.contentType] | <code>String</code> | 
| [options.apiType] | <code>String</code> | 

**Example**  
```js
<a name="axboot.gridBuilder"></a>

### axboot.gridBuilder(_config)
**Kind**: static method of <code>[axboot](#axboot)</code>  

| Param | Type |
| --- | --- |
| _config | <code>Object</code> | 

**Example**  
```js
<a name="axboot.extend"></a>

### axboot.extend(_obj1, _obj2)
1, 2를 믹스한 새로운 오브젝트를 반환

**Kind**: static method of <code>[axboot](#axboot)</code>  

| Param |
| --- |
| _obj1 | 
| _obj2 | 

<a name="axboot.actionExtend"></a>

### axboot.actionExtend([_actionThis], _action)
페이지에서 사용하는

**Kind**: static method of <code>[axboot](#axboot)</code>  

| Param | Type |
| --- | --- |
| [_actionThis] | <code>Object</code> | 
| _action | <code>Object</code> | 

**Example**  
```js
<a name="axMask"></a>

## axMask
기본 마스크

**Kind**: global variable  
**Example**  
```js
<a name="axDialogMask"></a>

## axDialogMask
다이얼로그용 마스크

**Kind**: global variable  
<a name="axAJAXMask"></a>

## axAJAXMask
ajax용 마스크

**Kind**: global variable  
<a name="axModal"></a>

## axModal
기본 모달

**Kind**: global variable  
<a name="axDialog"></a>

## axDialog
**Kind**: global variable  
<a name="axWarningDialog"></a>

## axWarningDialog
**Kind**: global variable  
<a name="axToast"></a>

## axToast
**Kind**: global variable  
**Example**  
```js
<a name="axWarningToast"></a>

## axWarningToast
**Kind**: global variable  