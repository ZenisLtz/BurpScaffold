package burp;

import org.zenis.BurpScaffold.*;
import org.zenis.BurpScaffold.Entity.Record;
import org.zenis.BurpScaffold.Service.DatabaseService;
import org.zenis.BurpScaffold.Service.RecordService;
import org.zenis.BurpScaffold.Utils.IOUtils;

import java.awt.*;
import java.io.*;
import java.sql.SQLException;
import java.util.*;
import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

public class BurpExtender extends JPanel implements IBurpExtender, ITab,
		IExtensionStateListener, IHttpListener, IContextMenuFactory, ListSelectionListener, IMessageEditorController {

	private static final String  progName="BurpScaffold";
	private static final String  author="zenis <sy5323@126.com>";
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	private UIComponent uicomponent;
	private IMessageEditor requestViewer, responseViewer;
	private RecordService rcdSVC = new RecordService();
	private DatabaseService dbSVC = new DatabaseService();

	private PrintWriter stdout;
	private OutputStream stderr;



	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		callbacks.setExtensionName("Burp Scaffold");
		callbacks.addSuiteTab(this);
		callbacks.registerHttpListener(this);
		callbacks.registerContextMenuFactory(this);
		callbacks.registerExtensionStateListener(this);
		this.helpers = callbacks.getHelpers();
		this.callbacks = callbacks;
		this.stdout = new PrintWriter(callbacks.getStdout(), true);
		this.stderr = callbacks.getStderr();

		requestViewer = callbacks.createMessageEditor(this, false);
		responseViewer = callbacks.createMessageEditor(this, false);

		uicomponent = new UIComponent(callbacks, stdout, stderr);
		uicomponent.registerGetSiteMap(rcdSVC, helpers);
		uicomponent.registerBcontrols(this, dbSVC, rcdSVC, requestViewer, responseViewer);

		setLayout(new BorderLayout());
		add(uicomponent.getParentJpanel(), BorderLayout.NORTH);
		add(uicomponent.getSplitPane(), BorderLayout.CENTER);


	}

	@Override public String  getTabCaption() { return  progName; }

	@Override public Component getUiComponent() { return this; }

	@Override public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo){}

	@Override public void extensionUnloaded() {
		try {
			dbSVC.DisconnectDB();
		} catch (Exception e) {
			IOUtils.reportError(BurpExtender.this, stderr, e, "Couldn't close database");
		}
	}

	@Override
	public java.util.List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
		final IHttpRequestResponse[] messages = invocation.getSelectedMessages();
		if (messages == null || messages.length == 0) return null;
		JMenuItem i = new JMenuItem("Import into " + progName);
		i.setEnabled(true);
		i.addActionListener(event -> {
			try {
				for (IHttpRequestResponse message : messages) {
					rcdSVC.insertRequestResponse(message, helpers);
				}
			} catch (SQLException e) {
				IOUtils.reportError(this, stderr, e, "Couldn't import selected messages");
			}
		});
		return Collections.singletonList(i);
	}

	public BurpExtender(){
		// TODO add UI to add/remove columns
	};

	private static final byte[] EMPTY_BYTE_ARRAY = {};

	@Override
	public void valueChanged(ListSelectionEvent e) {
		requestViewer.setMessage(getRequest(), true);
		responseViewer.setMessage(getResponse(), false);
	}

	@Override
	public IHttpService getHttpService() {
		Record rcd = rcdSVC.getRcdByID(uicomponent.getTblSVC().getSelectedId());
		if (rcd == null) return null;
		return new IHttpService() {
			public String  getHost() { return rcd.getHost(); }
			public int getPort() { return rcd.getPort(); }
			public String  getProtocol() { return rcd.getProtocol(); }
		};
	}

	@Override
	public byte[] getRequest() {
		Record rcd = rcdSVC.getRcdByID(uicomponent.getTblSVC().getSelectedId());
		if (rcd == null) return EMPTY_BYTE_ARRAY;
		return rcd.getRequest().getBytes();
	}

	@Override
	public byte[] getResponse() {
		Record rcd = rcdSVC.getRcdByID(uicomponent.getTblSVC().getSelectedId());
		if (rcd == null) return EMPTY_BYTE_ARRAY;
		return rcd.getResponse().getBytes();
	}
}

