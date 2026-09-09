using System;
using System.IO;
using System.Windows;
using System.Windows.Input;
using System.Windows.Forms;
using System.Windows.Data;

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Controls; // Added for TabItem, TabControl, SelectionChangedEventArgs

namespace Dependencies
{
    // Removed Dragablz.IInterTabClient and DependenciesInterTabClient class

    public class RecentMenuItem : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        public RecentMenuItem(string _Filepath)
        {
            Filepath = _Filepath;

            if (Properties.Settings.Default.FullPath)
                HeaderTitle = Filepath;
            else
                HeaderTitle = System.IO.Path.GetFileName(Filepath);

            Properties.Settings.Default.PropertyChanged += this.RecentMenuItem_PropertyChanged;
        }

        private void RecentMenuItem_PropertyChanged(object sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == "FullPath")
            {
                if (Properties.Settings.Default.FullPath)
                    HeaderTitle = Filepath;
                else
                    HeaderTitle = System.IO.Path.GetFileName(Filepath);

                if (PropertyChanged != null)
                {
                    PropertyChanged(this, new PropertyChangedEventArgs("HeaderTitle"));
                }
            }
        }

        public string Filepath {get; set;}

        public string HeaderTitle { get; set; }

    }

    /// <summary>
    /// MainWindow : container for displaying one or sereral DependencyWindow tree elements.
    /// </summary>
    public partial class MainWindow : Window
    {
        public static readonly RoutedUICommand OpenAboutCommand = new RoutedUICommand();
        public static readonly RoutedUICommand OpenUserSettingsCommand = new RoutedUICommand();
		public static readonly RoutedUICommand OpenCustomizeSearchFolderCommand = new RoutedUICommand();

        public ObservableCollection<RecentMenuItem> _recentsItems;

        // Removed _interTabClient field

        private About AboutPage;
        private UserSettings UserSettings;
		private SearchFolder SearchFolder;

        private bool _Master;

        public ICommand CloseTabCommand { get; private set; }


        #region PublicAPI
        public MainWindow()
        {

            InitializeComponent();

            _recentsItems = new ObservableCollection<RecentMenuItem>();
            PopulateRecentFilesMenuItems();

            this.AboutPage = new About();
            this.UserSettings = new UserSettings();
			this.SearchFolder = null;

            // Removed Dragablz-specific initialization
            // this.TabControl.InterTabController.InterTabClient = DoNothingInterTabClient;
            // this.TabControl.IsEmptyChanged += MainWindow_TabControlIsEmptyHandler;

            this._Master = false;
			this.DataContext = this;

            CloseTabCommand = new RelayCommand(CloseTab);
            this.TabControl.SelectionChanged += TabControl_SelectionChanged;

            UpdateTabControlState();
        }

        public ObservableCollection<RecentMenuItem> RecentsItems
        {
            get
            {
                return _recentsItems;
            }
        }

        /// <summary>
        /// Open a new depedency tree window on a given PE.
        /// </summary>
        /// <param name="Filename">File path to a PE to process.</param>
        public void OpenNewDependencyWindow(String Filename)
        {
            var newDependencyWindow = new DependencyWindow(Filename);
            // Removed Dragablz-specific header assignment
            // newDependencyWindow.Header = new CustomHeaderViewModel { Header = Path.GetFileNameWithoutExtension(Filename) };

            TabItem newTabItem = new TabItem();
            newTabItem.Header = Path.GetFileNameWithoutExtension(Filename); // Set header directly
            newTabItem.Content = newDependencyWindow; // Set content

            this.TabControl.Items.Add(newTabItem); // Add to native TabControl
            this.TabControl.SelectedItem = newTabItem; // Select the new tab

            // Update recent files entries
            App.AddToRecentDocuments(Filename);
            PopulateRecentFilesMenuItems();
            UpdateTabControlState(); // Update state after adding a tab
        }

        // Removed DoNothingInterTabClient property
		
		public bool EnableSearchFolderCustomization
		{
			// find a way to update the toggle based on the number of window opened without relying on
			// creating a custom IsEnabledChanged event
			get { return true;/*this.TabControl.SelectedItem != null;*/ }
		}

		/// <summary>
		/// When closing all tabs on a particular MainWindow instances, we want
		/// to know if it's okay to close the application also. the MainWindow created
		/// by the "App" entry point is marked as "master" and is not closed,
		/// whereas all the others are.
		/// </summary>
		public bool IsMaster
        {
            get { return _Master; }
            set { _Master = value; }
        }


        #endregion PublicAPI

        /// <summary>
        /// Populate "recent entries" menu items
        /// </summary>
        public void PopulateRecentFilesMenuItems()
        {

            //System.Windows.Controls.MenuItem FileMenuItem = (System.Windows.Controls.MenuItem)this.MainMenu.Items[0];
            

            if (Properties.Settings.Default.RecentFiles.Count == 0) {
                return;
            }


            foreach (var RecentFilePath in Properties.Settings.Default.RecentFiles)
            {
                // Ignore empty dummy entries
                if (String.IsNullOrEmpty(RecentFilePath))
                {
                    continue;
                }

                AddRecentFilesMenuItem(RecentFilePath, Properties.Settings.Default.RecentFiles.IndexOf(RecentFilePath));
            }
        }


        private void AddRecentFilesMenuItem(string Filepath, int index)
        {

            //System.Windows.Controls.MenuItem FileMenuItem = (System.Windows.Controls.MenuItem)this.MainMenu.Items[0];

            // Create new menu item
            //System.Windows.Controls.MenuItem newRecentFileItem = new System.Windows.Controls.MenuItem();
            //newRecentFileItem.DataContext = Filepath;
            //newRecentFileItem.Click += new RoutedEventHandler(RecentFileCommandBinding_Clicked);
            //newRecentFileItem.Style = "FullpathStyle";

            //RecentsItems.Add(new RecentMenuItem {
            //    MenuItemName = "Edit"
            //});
            //RecentsItems.Add(
            //    new RecentMenuItem{
            //        MenuItemName = "Search"
            //    }
            //);

            RecentsItems.Add(new RecentMenuItem(Filepath));
            



            //// check if the item already is in the list, diregarding others menu items
            //if (index + 5 < FileMenuItem.Items.Count)
            //{
            //    FileMenuItem.Items[3 + index] = newRecentFileItem;
            //}
            //else
            //{
            //    // Add it to the list at the top
            //    FileMenuItem.Items.Insert(3, newRecentFileItem);
            //}

        }

        #region Commands
        private void RecentFileCommandBinding_Clicked(object sender, RoutedEventArgs e)
        {
            System.Windows.Controls.MenuItem RecentFile = sender as System.Windows.Controls.MenuItem;
            String RecentFilePath = (RecentFile.DataContext as RecentMenuItem).Filepath;

            if (RecentFilePath.Length != 0 )
            {
                OpenNewDependencyWindow(RecentFilePath);
            }

        }

        private void OpenCommandBinding_Executed(object sender, RoutedEventArgs e)
        {
            OpenFileDialog InputFileNameDlg = new OpenFileDialog
            {
                Filter = "exe files (*.exe, *.dll)| *.exe;*.dll; | All files (*.*)|*.*",
                FilterIndex = 0,
                RestoreDirectory = true,
                
            };
            

            if (InputFileNameDlg.ShowDialog() != System.Windows.Forms.DialogResult.OK)
                return;

            OpenNewDependencyWindow(InputFileNameDlg.FileName);

        }

        private void ExitCommandBinding_Executed(object sender, RoutedEventArgs e)
        {
            System.Windows.Application.Current.Shutdown();
        }

        private void OpenAboutCommandBinding_Executed(object sender, RoutedEventArgs e)
        {
            this.AboutPage.Close();
            this.AboutPage = new About();
            this.AboutPage.Show();
        }

        private void OpenUserSettingsCommandBinding_Executed(object sender, RoutedEventArgs e)
        {
            this.UserSettings.Close();
            this.UserSettings = new UserSettings();
            this.UserSettings.Owner = this;
            this.UserSettings.Show();
        }

		private void OpenCustomizeSearchFolderCommand_Executed(object sender, RoutedEventArgs e)
		{
			DependencyWindow SelectedItem = (this.TabControl.SelectedItem as TabItem)?.Content as DependencyWindow;
			if (SelectedItem == null)
				return;

			if (this.SearchFolder != null)
			{
				this.SearchFolder.Close();
			}
			
			this.SearchFolder = new SearchFolder(SelectedItem);
			this.SearchFolder.Show();
		}


		private void RefreshCommandBinding_Executed(object sender, RoutedEventArgs e)
        {
			DependencyWindow SelectedItem = (this.TabControl.SelectedItem as TabItem)?.Content as DependencyWindow;
			if (SelectedItem == null)
				return;

			SelectedItem.InitializeView();
        }
        #endregion Commands

        #region EventsHandler

        /// <summary>
        /// Application.Close event handler. Save user settings and close every child windows.
        /// </summary>
        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            this.UserSettings.Close();
            this.AboutPage.Close();

			if (this.SearchFolder!= null)
			{
				this.SearchFolder.Close();
			}
			


			base.OnClosing(e);
        }

        /// <summary>
        /// file drag-and-drop event handler.
        /// </summary>
        private void MainWindow_Drop(object sender, System.Windows.DragEventArgs e)
        {
            if (e.Data.GetDataPresent(System.Windows.Forms.DataFormats.FileDrop))
            {
                string[] files = (string[])e.Data.GetData(System.Windows.Forms.DataFormats.FileDrop);
                
                foreach (var file in files)
                {
                    OpenNewDependencyWindow(file);
                }
            }
        }

        // Removed MainWindow_TabControlIsEmptyHandler

        private void UpdateTabControlState()
        {
            bool hasItems = TabControl.Items.Count > 0;
            DefaultMessage.Visibility = hasItems ? Visibility.Hidden : Visibility.Visible;
            _RefreshItem.IsEnabled = hasItems;
        }

        private void TabControl_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateTabControlState();
        }

        private void CloseTab(object parameter)
        {
            if (parameter is TabItem tabItemToRemove)
            {
                TabControl.Items.Remove(tabItemToRemove);
                UpdateTabControlState();
            }
        }

        #endregion EventsHandler
    }

    /// <summary>
    /// Converter to transform a boolean into a Visibility settings. 
    /// Why is this not part of the WPF standard lib ? Everybody ends up coding one in every project.
    /// </summary>
    public class BooleanToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            Boolean SettingValue = (Boolean) value;

            if (SettingValue)
                return Visibility.Visible;

            return Visibility.Collapsed;

        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}